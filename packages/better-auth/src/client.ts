// better-auth クライアントプラグイン。
//   authClient.signIn.concrnt({ callbackURL, onChallenge })   Concrnt でログイン (未登録の CCID はサインアップ)
//   authClient.concrnt.link({ callbackURL, onChallenge })      ログイン中のユーザーに CCID を追加
//   一覧・解除は better-auth 組み込みの authClient.listAccounts() / authClient.unlinkAccount({ accountId })
//
// 応答方式 (CIP-17 §8) はサーバーに現れない。1 つの要求から QR 用 (directPostUri) と同一端末リンク用 (fragmentUri) の
// 両方が返るので、onChallenge で QR を描き、同じ端末にアプリがあればリンクへ遷移する。
//   別端末 (§8.1): このクライアントが status をポーリングし、ok になれば cookie が入っている
//   同一端末 (§8.2): サーバーの着地ページが exchange まで済ませて callbackURL に戻す。戻ったときには cookie が入っている
import type { BetterAuthClientPlugin, ClientStore } from '@better-auth/core'
import type { BetterFetch, BetterFetchOption } from 'better-auth/client'
import type { concrnt } from './index.js'

export interface ConcrntChallenge {
    /** QR にする Authorization Request URI (concrnt-auth://direct_post/…) */
    directPostUri: string
    /** 同一端末で開くリンク (concrnt-auth://fragment/…) */
    fragmentUri: string
    /** QR の横に表示する絵文字。Authenticator の同意画面と見比べる (§6) */
    displayCode: string
    /** 要求の失効時刻 (UNIX 秒) */
    exp: number
}

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
    | { status: 'denied'; callbackURL: string }
    | { status: 'expired' }
    | { status: 'aborted' }

type FlowError = { code?: string | undefined; message?: string | undefined; status: number; statusText: string }
type FlowReturn = { data: ConcrntFlowResult; error: null } | { data: null; error: FlowError }

interface Started extends ConcrntChallenge {
    pollToken: string
}

type StatusResponse =
    | { status: 'pending' }
    | { status: 'denied'; callbackURL: string }
    | { status: 'ok'; callbackURL: string; isNewUser: boolean; token: string; user: Record<string, unknown> }

export const getConcrntActions = ($fetch: BetterFetch, $store: ClientStore) => {
    const run = async (link: boolean, opts: ConcrntFlowOptions): Promise<FlowReturn> => {
        const started = await $fetch<Started>('/concrnt/start', {
            method: 'POST',
            body: { callbackURL: opts.callbackURL, newUserCallbackURL: opts.newUserCallbackURL, ...(link ? { link: true } : {}) },
            ...opts.fetchOptions,
            throw: false
        })
        if (!started.data) return started as FlowReturn
        const { directPostUri, fragmentUri, displayCode, exp, pollToken } = started.data
        opts.onChallenge?.({ directPostUri, fragmentUri, displayCode, exp })

        // §8.1: 開始したブラウザの秘密 (pollToken) で結果を待つ
        const interval = opts.pollIntervalMs ?? 2000
        while (true) {
            if (opts.signal?.aborted) return { data: { status: 'aborted' }, error: null }
            if (Date.now() / 1000 >= exp) return { data: { status: 'expired' }, error: null }
            const res = await $fetch<StatusResponse>('/concrnt/status', { method: 'POST', body: { pollToken }, ...opts.fetchOptions, throw: false })
            if (res.error) return res as FlowReturn
            if (res.data?.status === 'ok') {
                $store.notify('$sessionSignal')
                return { data: res.data, error: null }
            }
            if (res.data?.status === 'denied') return { data: res.data, error: null }
            await sleep(interval, opts.signal)
        }
    }

    return {
        signIn: {
            /** CIP-17 でログインする。未登録の CCID はサインアップ (サーバーの disableSignUp で禁止可) */
            concrnt: (opts: ConcrntFlowOptions = {}) => run(false, opts)
        },
        concrnt: {
            /** ログイン中のユーザーに CCID を追加する。開始したセッションを持つブラウザだけが完了できる */
            link: (opts: ConcrntFlowOptions = {}) => run(true, opts)
        },
        $Infer: {} as { ConcrntFlowResult: ConcrntFlowResult; ConcrntChallenge: ConcrntChallenge }
    }
}

const sleep = (ms: number, signal: AbortSignal | undefined): Promise<void> =>
    new Promise((resolve) => {
        const timer = setTimeout(() => {
            signal?.removeEventListener('abort', onAbort)
            resolve()
        }, ms)
        const onAbort = () => {
            clearTimeout(timer)
            resolve()
        }
        signal?.addEventListener('abort', onAbort, { once: true })
    })

export const concrntClient = () =>
    ({
        id: 'concrnt',
        $InferServerPlugin: {} as ReturnType<typeof concrnt>,
        getActions: ($fetch, $store) => getConcrntActions($fetch, $store),
        pathMethods: {
            '/concrnt/start': 'POST',
            '/concrnt/status': 'POST'
        }
    }) satisfies BetterAuthClientPlugin
