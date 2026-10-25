// 統合テスト用の小さな RP: better-auth + node:sqlite (D1 と同じ SQLite) に concrnt() を差し込み、auth.handler を直接叩く
import { DatabaseSync } from 'node:sqlite'
import { betterAuth } from 'better-auth'
import { concrnt, type ConcrntPluginOptions } from '../src/index.js'
import { issueIdToken, makeIdentity, parseRequestUri, type IdTokenOverrides, type TestIdentity, type TestRequest } from '../../auth-client/test/authenticator.js'

export { makeIdentity, type TestIdentity }

export const ORIGIN = 'https://rp.test'
export const BASE_PATH = '/api/auth'

export const createTestAuth = async (options: ConcrntPluginOptions = {}, trustedOrigins: string[] = ['https://app.test']) => {
    const auth = betterAuth({
        appName: 'Test RP',
        database: new DatabaseSync(':memory:'),
        secret: 'test-secret-test-secret-test-secret',
        baseURL: ORIGIN,
        basePath: BASE_PATH,
        trustedOrigins,
        emailAndPassword: { enabled: true },
        rateLimit: { enabled: false },
        // NODE_ENV=test では better-auth が origin check を自動で切るので、本番と同じ挙動に戻す
        advanced: { disableOriginCheck: false, disableCSRFCheck: false, database: { validateSchema: false } },
        plugins: [concrnt(options)]
    })
    await (await auth.$context).runMigrations()
    return auth
}

export type TestAuth = Awaited<ReturnType<typeof createTestAuth>>

export interface CallOptions {
    json?: unknown
    form?: Record<string, string>
    headers?: HeadersInit
    /** Authenticator (ネイティブアプリ) からの呼び出し: ブラウザが付ける Origin ヘッダーを付けない */
    authenticator?: boolean
}

/** path は basePath 配下 (`/concrnt/...`) か絶対 URL。既定ではブラウザからの呼び出しとして Origin を付ける */
export const call = (auth: TestAuth, method: string, path: string, { json, form, headers, authenticator }: CallOptions = {}): Promise<Response> => {
    const url = path.startsWith('https://') ? path : `${ORIGIN}${BASE_PATH}${path}`
    const h = new Headers(headers)
    if (!authenticator && method !== 'GET') h.set('origin', ORIGIN)
    let body: BodyInit | undefined
    if (json !== undefined) {
        h.set('content-type', 'application/json')
        body = JSON.stringify(json)
    } else if (form) {
        h.set('content-type', 'application/x-www-form-urlencoded')
        body = new URLSearchParams(form).toString()
    }
    return auth.handler(new Request(url, { method, headers: h, body }))
}

export const json = async <T = Record<string, unknown>>(res: Response): Promise<T> => (await res.json()) as T

/** Set-Cookie を次のリクエストの Cookie ヘッダーにする */
export const cookiesOf = (res: Response): Headers => {
    const pairs = res.headers.getSetCookie().map((line) => line.split(';')[0]!.trim()).filter((kv) => !/=;?$/.test(kv))
    return new Headers(pairs.length ? { cookie: pairs.join('; ') } : {})
}

export const hasSessionCookie = (res: Response): boolean => /better-auth\.session_token=[^;]+;/.test(res.headers.get('set-cookie') ?? '')

export interface Started {
    postUri: string
    fragmentUri: string
    displayCode: string
    exp: number
    pollToken: string
}

/** 送り先 URL のクエリ無しの形。実際の送り先 (= aud) はこれに `?n=…` が付く (要求ごとに変わる) */
export const CALLBACK_URL = `${ORIGIN}${BASE_PATH}/concrnt/callback`

/** ブラウザ: 開始 */
export const start = async (auth: TestAuth, body: Record<string, unknown> = {}, headers?: HeadersInit) => {
    const res = await call(auth, 'POST', '/concrnt/start', { json: body, headers })
    return { res, started: (res.ok ? await res.json() : null) as Started | null }
}

/** Authenticator: URI を解釈する (n と aud = "https://" + <rest>) */
export const requestOf = (started: Started) => parseRequestUri(started.postUri)
export const nonceOf = (started: Started): string => requestOf(started).nonce

/** Authenticator: ID Token を作る (aud は送り先 URL = "https://" + <rest>)。nonce 文字列だけ渡したときは aud をクエリ無しの形にする (不正ケース用) */
export const idTokenFor = (identity: TestIdentity, request: TestRequest | string, overrides: IdTokenOverrides = {}): string =>
    issueIdToken(identity, typeof request === 'string' ? { nonce: request, audience: `${CALLBACK_URL}?n=${request}` } : request, Math.floor(Date.now() / 1000), overrides)

/** Authenticator: §8.1 post。送り先は <rest> (クエリ込み)。request を省略すると (拒否応答など) クエリ無しの URL に送る */
export const post = (auth: TestAuth, form: Record<string, string>, request?: { redirectUri: string }): Promise<Response> =>
    call(auth, 'POST', request ? request.redirectUri : CALLBACK_URL, { form, authenticator: true })

/** ブラウザ: §8.1 ポーリング */
export const poll = (auth: TestAuth, started: Started, headers?: HeadersInit): Promise<Response> =>
    call(auth, 'POST', '/concrnt/status', { json: { pollToken: started.pollToken }, headers })

/** ブラウザ (着地ページ): §8.2 exchange */
export const exchange = (auth: TestAuth, body: { id_token?: string | null; error?: string | null; nonce?: string | null }, headers?: HeadersInit): Promise<Response> =>
    call(auth, 'POST', '/concrnt/exchange', { json: body, headers })

/** 別端末フローを最後まで (開始 → URI を読む → post → ポーリング)。headers は開始とポーリングの両方に付く */
export const postFlow = async (auth: TestAuth, identity: TestIdentity, startBody: Record<string, unknown> = {}, headers?: HeadersInit) => {
    const { res: startRes, started } = await start(auth, startBody, headers)
    if (!started) throw new Error(`start failed: ${startRes.status} ${await startRes.text()}`)
    const request = requestOf(started)
    const posted = await post(auth, { id_token: idTokenFor(identity, request) }, request)
    const polled = await poll(auth, started, headers)
    return { started, request, nonce: request.nonce, posted, polled }
}

let userSeq = 0
/** メール/パスワードでユーザーを作り、そのセッション cookie を返す */
export const signUpUser = async (auth: TestAuth, name = `user${++userSeq}`) => {
    const res = await call(auth, 'POST', '/sign-up/email', { json: { email: `${name}@example.test`, password: 'password-1234', name } })
    if (!res.ok) throw new Error(`sign-up failed: ${res.status} ${await res.text()}`)
    const body = await json<{ user: { id: string; name: string } }>(res)
    return { user: body.user, headers: cookiesOf(res) }
}

export const getSession = async (auth: TestAuth, headers: HeadersInit) => {
    const res = await call(auth, 'GET', '/get-session', { headers })
    return (await res.json()) as { user: { id: string; name: string; email: string; image?: string | null } } | null
}

export interface AccountRow {
    id: string
    providerId: string
    accountId: string
}

export const listAccounts = async (auth: TestAuth, headers: HeadersInit): Promise<AccountRow[]> => json<AccountRow[]>(await call(auth, 'GET', '/list-accounts', { headers }))
