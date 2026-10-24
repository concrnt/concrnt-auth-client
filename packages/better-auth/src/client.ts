// better-auth クライアントプラグイン。
//   authClient.signIn.concrnt({ callbackURL, onChallenge })   Concrnt でログイン (未登録の CCID はサインアップ)
//   authClient.concrnt.pendingSignUp() / concrnt.signUp()      サーバーが signUp: 'confirm' のとき。結果 'signup_required' の後に
//                                                              確認画面を出し、「作る」なら signUp()。断るなら何も呼ばず次のログインへ
//   ログイン中の CCID は better-auth 組み込みの authClient.listAccounts() の providerId 'concrnt' の行
//
// 応答方式 (CIP-17 §8) はサーバーに現れない。1 つの要求から QR 用 (directPostUri) と同一端末リンク用 (fragmentUri) の
// 両方が返るので、onChallenge で QR を描き、同じ端末にアプリがあればリンクへ遷移する。
//   別端末 (§8.1): このクライアントが status をポーリングし、ok になれば cookie が入っている
//   同一端末 (§8.2): サーバーの着地ページが exchange まで済ませて callbackURL に戻す。戻ったときには cookie が入っている
// 流れ (開始 → onChallenge → ポーリング → 終端) は @concrnt/auth-client/browser の runLogin
import type { BetterAuthClientPlugin, ClientStore } from '@better-auth/core'
import type { BetterFetch, BetterFetchOption } from 'better-auth/client'
import { runLogin, type LoginChallenge, type LoginStartResponse } from '@concrnt/auth-client/browser'
import type { concrnt, PendingProfile } from './index.js'

export type { PendingProfile }
export type ConcrntChallenge = LoginChallenge

export interface ConcrntFlowOptions {
    /** ログイン後に戻る URL (fragment では着地ページがここへ遷移する)。trustedOrigins の範囲内であること。既定 '/' */
    callbackURL?: string | undefined
    /** 新しいユーザーが作られたときの戻り先 (OAuth の newUserCallbackURL と同じ)。省略時は callbackURL */
    newUserCallbackURL?: string | undefined
    /** 要求が発行されたときに呼ばれる。QR と displayCode を描き、必要なら fragmentUri へ遷移する */
    onChallenge?: ((challenge: ConcrntChallenge) => void) | undefined
    /** status のポーリング間隔 (ms)。既定 2000 */
    pollIntervalMs?: number | undefined
    /** 待機を中断する */
    signal?: AbortSignal | undefined
    fetchOptions?: BetterFetchOption | undefined
}

export type ConcrntFlowResult =
    | { status: 'ok'; callbackURL: string; isNewUser: boolean; token: string; user: Record<string, unknown> }
    /** サーバーが signUp: 'confirm' で、未登録の CCID だった。concrnt.signUp() で作る */
    | { status: 'signup_required'; callbackURL: string; profile: PendingProfile }
    | { status: 'denied'; callbackURL: string }
    | { status: 'expired' }
    | { status: 'aborted' }

type FlowError = { code?: string | undefined; message?: string | undefined; status: number; statusText: string }
type FlowReturn = { data: ConcrntFlowResult; error: null } | { data: null; error: FlowError }

type StatusResponse = { status: 'pending' } | Exclude<ConcrntFlowResult, { status: 'expired' | 'aborted' }>

/** $fetch の error をそのまま運ぶための例外 */
class FetchFailed extends Error {
    readonly error: FlowError
    constructor(error: FlowError) {
        super(error.message ?? error.statusText)
        this.error = error
    }
}

export const getConcrntActions = ($fetch: BetterFetch, $store: ClientStore) => {
    const run = async (opts: ConcrntFlowOptions): Promise<FlowReturn> => {
        const unwrap = <T>(res: { data: T | null; error: FlowError | null }): T => {
            if (res.error || res.data === null) throw new FetchFailed(res.error ?? { status: 0, statusText: 'no data' })
            return res.data
        }
        try {
            const result = await runLogin<Exclude<StatusResponse, { status: 'pending' }>>({
                start: async () =>
                    unwrap(
                        await $fetch<LoginStartResponse>('/concrnt/start', {
                            method: 'POST',
                            body: { callbackURL: opts.callbackURL, newUserCallbackURL: opts.newUserCallbackURL },
                            ...opts.fetchOptions,
                            throw: false
                        })
                    ),
                // §8.1: 開始したブラウザの秘密 (pollToken) で結果を待つ
                poll: async (pollToken) => unwrap(await $fetch<StatusResponse>('/concrnt/status', { method: 'POST', body: { pollToken }, ...opts.fetchOptions, throw: false })),
                onChallenge: opts.onChallenge,
                pollIntervalMs: opts.pollIntervalMs,
                signal: opts.signal
            })
            if (result.status === 'ok') $store.notify('$sessionSignal')
            return { data: result, error: null }
        } catch (e) {
            if (e instanceof FetchFailed) return { data: null, error: e.error }
            throw e
        }
    }

    return {
        signIn: {
            /** CIP-17 でログインする。未登録の CCID はサインアップ (サーバーの signUp で確認・禁止にできる) */
            concrnt: (opts: ConcrntFlowOptions = {}) => run(opts)
        },
        $Infer: {} as { ConcrntFlowResult: ConcrntFlowResult; ConcrntChallenge: ConcrntChallenge }
    }
}

export const concrntClient = () =>
    ({
        id: 'concrnt',
        $InferServerPlugin: {} as ReturnType<typeof concrnt>,
        getActions: ($fetch, $store) => getConcrntActions($fetch, $store),
        pathMethods: {
            '/concrnt/start': 'POST',
            '/concrnt/status': 'POST',
            '/concrnt/sign-up': 'POST',
            '/concrnt/pending-sign-up': 'GET'
        },
        // concrnt.signUp() はセッションを作るので useSession を更新する (pendingSignUp / signUp 自体はサーバー endpoint から推論される)
        atomListeners: [{ matcher: (path) => path === '/concrnt/sign-up', signal: '$sessionSignal' }]
    }) satisfies BetterAuthClientPlugin
