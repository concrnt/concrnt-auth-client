// 統合テスト用の小さな RP: better-auth + node:sqlite (D1 と同じ SQLite) に concrnt() を差し込み、auth.handler を直接叩く
import { DatabaseSync } from 'node:sqlite'
import { betterAuth } from 'better-auth'
import type { RequestObject } from '@concrnt/auth-client'
import { concrnt, type ConcrntPluginOptions } from '../src/index.js'
import { issueIdToken, makeIdentity, type IdTokenOverrides, type TestIdentity } from '../../auth-client/test/authenticator.js'

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
    requestUri: string
    directPostUri: string
    fragmentUri: string
    displayCode: string
    exp: number
    pollToken: string
}

/** ブラウザ: 開始 */
export const start = async (auth: TestAuth, kind: 'authentication' | 'registration', body: Record<string, unknown> = {}, headers?: HeadersInit) => {
    const res = await call(auth, 'POST', `/concrnt/start-${kind}`, { json: body, headers })
    return { res, started: (res.ok ? await res.json() : null) as Started | null }
}

export const challengeOf = (requestUri: string): string => requestUri.slice(requestUri.lastIndexOf('/') + 1)

/** Authenticator: Request Object を取りに行く */
export const fetchRequestObject = async (auth: TestAuth, started: Started): Promise<RequestObject> => {
    const res = await call(auth, 'GET', started.requestUri, { authenticator: true })
    if (!res.ok) throw new Error(`request object: ${res.status} ${await res.text()}`)
    return json<RequestObject>(res)
}

/** Authenticator: ID Token を作る */
export const idTokenFor = (identity: TestIdentity, ro: RequestObject, overrides: IdTokenOverrides = {}): string =>
    issueIdToken(identity, ro, ORIGIN, Math.floor(Date.now() / 1000), overrides)

/** Authenticator: §8.1 direct_post */
export const directPost = (auth: TestAuth, ro: RequestObject, form: Record<string, string>): Promise<Response> =>
    call(auth, 'POST', ro.redirect_uri, { form, authenticator: true })

/** ブラウザ: §8.1 ポーリング */
export const poll = (auth: TestAuth, started: Started, headers?: HeadersInit): Promise<Response> =>
    call(auth, 'GET', `/concrnt/status?pollToken=${encodeURIComponent(started.pollToken)}`, { headers })

/** ブラウザ (着地ページ): §8.2 exchange */
export const exchange = (auth: TestAuth, ro: RequestObject, body: { id_token?: string | null; error?: string | null }, headers?: HeadersInit): Promise<Response> =>
    call(auth, 'POST', ro.redirect_uri.replace('/concrnt/callback/', '/concrnt/exchange/'), { json: body, headers })

/** 別端末フローを最後まで (開始 → RO → direct_post → ポーリング) */
export const directPostFlow = async (auth: TestAuth, kind: 'authentication' | 'registration', identity: TestIdentity, startBody: Record<string, unknown> = {}, headers?: HeadersInit) => {
    const { res: startRes, started } = await start(auth, kind, startBody, headers)
    if (!started) throw new Error(`start failed: ${startRes.status} ${await startRes.text()}`)
    const ro = await fetchRequestObject(auth, started)
    const posted = await directPost(auth, ro, { id_token: idTokenFor(identity, ro) })
    const polled = await poll(auth, started, headers)
    return { started, ro, posted, polled }
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
