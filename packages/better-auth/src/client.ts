// better-auth クライアントプラグイン。パスキーの passkeyClient と同じ形:
//   authClient.signIn.concrnt({ mode, callbackURL, onChallenge })      認証
//   authClient.concrnt.addIdentity({ mode, callbackURL, name, ... })   ログイン中のユーザーに CCID を追加 (登録)
//   authClient.concrnt.listIdentities / deleteIdentity / updateIdentity (サーバー endpoint から推論)
//   authClient.useListIdentities()
//
// 応答方式 (CIP-17 §8) を選ぶのはここ:
//   'fragment'    同一端末。fragmentUri へ遷移して Authenticator アプリに渡す。着地と exchange はサーバーの着地ページが済ませ、
//                 callbackURL に戻ってきたときには cookie が入っている
//   'direct_post' 別端末。onChallenge で QR 用 URI と display_code を渡し、status をポーリングして結果を待つ
import type { BetterAuthClientPlugin, ClientStore } from '@better-auth/core'
import { useAuthQuery, type BetterFetch, type BetterFetchOption } from 'better-auth/client'
import { atom } from 'nanostores'
import type { concrnt } from './index.js'
import type { ConcrntIdentity } from './schema.js'

export type { ConcrntIdentity }

export type ConcrntResponseMode = 'fragment' | 'direct_post'

export interface ConcrntStarted {
    requestUri: string
    directPostUri: string
    fragmentUri: string
    displayCode: string
    exp: number
    pollToken: string
}

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
    /** 既定 'direct_post' */
    mode?: ConcrntResponseMode | undefined
    /** ログイン後に戻る URL。fragment では着地ページがここへ遷移する。trustedOrigins の範囲内であること */
    callbackURL?: string | undefined
    /** 要求が発行されたときに呼ばれる。direct_post ではここで QR と displayCode を描く */
    onChallenge?: ((challenge: ConcrntChallenge) => void) | undefined
    /** direct_post のポーリング間隔 (ms)。既定 2000 */
    pollIntervalMs?: number | undefined
    /** direct_post の待機を中断する */
    signal?: AbortSignal | undefined
    fetchOptions?: BetterFetchOption | undefined
}

export interface ConcrntAddIdentityOptions extends ConcrntFlowOptions {
    /** identity に付けるラベル */
    name?: string | undefined
    /** サーバーの registration.resolveUser / afterVerification に渡す任意の文字列 */
    context?: string | undefined
    /** 登録成功後にセッションも作る (未ログインからの登録用) */
    createSession?: boolean | undefined
}

export type ConcrntFlowResult =
    | { status: 'ok'; callbackURL: string; data: Record<string, unknown> }
    | { status: 'denied'; callbackURL: string }
    | { status: 'expired' }
    | { status: 'aborted' }
    | { status: 'redirect' }

type FlowError = { code: string; message: string; status: number; statusText: string }
type FlowReturn = { data: ConcrntFlowResult; error: null } | { data: null; error: FlowError }

const errorOf = (code: string, message: string, status = 400): FlowReturn => ({
    data: null,
    error: { code, message, status, statusText: status === 400 ? 'BAD_REQUEST' : 'INTERNAL_SERVER_ERROR' }
})

export const getConcrntActions = ($fetch: BetterFetch, { $listIdentities, $store }: { $listIdentities: ReturnType<typeof atom<number>>; $store: ClientStore }) => {
    const run = async (startPath: string, startBody: Record<string, unknown>, opts: ConcrntFlowOptions, notifySession: boolean): Promise<FlowReturn> => {
        const mode = opts.mode ?? 'direct_post'
        const started = await $fetch<ConcrntStarted>(startPath, {
            method: 'POST',
            body: { callbackURL: opts.callbackURL, ...startBody },
            ...opts.fetchOptions,
            throw: false
        })
        if (!started.data) return started as FlowReturn
        const { directPostUri, fragmentUri, displayCode, exp, pollToken } = started.data
        opts.onChallenge?.({ directPostUri, fragmentUri, displayCode, exp })

        if (mode === 'fragment') {
            if (typeof window === 'undefined') return errorOf('NO_WINDOW', 'fragment mode requires a browser window', 500)
            // Authenticator アプリへ。戻りはサーバーの着地ページが callbackURL へ遷移させる
            window.location.href = fragmentUri
            return { data: { status: 'redirect' }, error: null }
        }

        // direct_post: 開始したブラウザの秘密 (pollToken) で結果を待つ (§8.1)
        const interval = opts.pollIntervalMs ?? 2000
        while (true) {
            if (opts.signal?.aborted) return { data: { status: 'aborted' }, error: null }
            if (Date.now() / 1000 >= exp) return { data: { status: 'expired' }, error: null }
            const res = await $fetch<{ status: 'pending' | 'ok' | 'denied'; callbackURL?: string } & Record<string, unknown>>('/concrnt/status', {
                method: 'GET',
                query: { pollToken },
                ...opts.fetchOptions,
                throw: false
            })
            if (res.error) return res as FlowReturn
            if (res.data?.status === 'ok') {
                $listIdentities.set(Math.random())
                if (notifySession) $store.notify('$sessionSignal')
                return { data: { status: 'ok', callbackURL: res.data.callbackURL ?? '/', data: res.data }, error: null }
            }
            if (res.data?.status === 'denied') return { data: { status: 'denied', callbackURL: res.data.callbackURL ?? '/' }, error: null }
            await new Promise<void>((resolve) => {
                const timer = setTimeout(() => {
                    opts.signal?.removeEventListener('abort', onAbort)
                    resolve()
                }, interval)
                const onAbort = () => {
                    clearTimeout(timer)
                    resolve()
                }
                opts.signal?.addEventListener('abort', onAbort, { once: true })
            })
        }
    }

    return {
        signIn: {
            /** CIP-17 で認証する。登録済みの CCID だけがログインできる */
            concrnt: (opts: ConcrntFlowOptions = {}) => run('/concrnt/start-authentication', {}, opts, true)
        },
        concrnt: {
            /** CCID をユーザーに追加する (サーバーの registration 設定に従う) */
            addIdentity: (opts: ConcrntAddIdentityOptions = {}) =>
                run(
                    '/concrnt/start-registration',
                    { name: opts.name, context: opts.context, ...(opts.createSession ? { createSession: true } : {}) },
                    opts,
                    opts.createSession ?? false
                )
        },
        $Infer: {} as { ConcrntFlowResult: ConcrntFlowResult; ConcrntChallenge: ConcrntChallenge }
    }
}

export const concrntClient = () => {
    const $listIdentities = atom<number>(0)
    return {
        id: 'concrnt',
        $InferServerPlugin: {} as ReturnType<typeof concrnt>,
        getActions: ($fetch, $store) => getConcrntActions($fetch, { $listIdentities, $store }),
        getAtoms($fetch) {
            return {
                listIdentities: useAuthQuery<ConcrntIdentity[]>($listIdentities, '/concrnt/list-identities', $fetch, { method: 'GET' }),
                $listIdentities
            }
        },
        pathMethods: {
            '/concrnt/start-authentication': 'POST',
            '/concrnt/start-registration': 'POST',
            '/concrnt/delete-identity': 'POST',
            '/concrnt/update-identity': 'POST'
        },
        atomListeners: [
            {
                matcher: (path) => path === '/concrnt/delete-identity' || path === '/concrnt/update-identity' || path === '/sign-out',
                signal: '$listIdentities'
            }
        ]
    } satisfies BetterAuthClientPlugin
}
