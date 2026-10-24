// CIP-17 (Sign-In with Concrnt) の RP (Relying Party) 側サンプル。プロトコル処理は @concrnt/auth-client に任せ、
// ここにはルーティングとログイン後のセッション (worker/session.ts) だけがある。
//
//   ブラウザ (src/App.tsx)        この Worker                              Authenticator (world-app)
//   ---------------------        -----------                              -------------------------
//   POST /api/login/start -----> auth.start()             要求の行を D1 に置き、QR 用 / リンク用 URI と pollToken を返す
//                                                         <-QR/link-- GET  /auth/request/:C  → auth.getRequestObject(C)
//   --- 別端末 (direct_post) ---
//                                                         <----------- POST /auth/callback/:C → auth.receiveDirectPost(C) → 結果を預ける
//   POST /api/login/status ----> auth.pollResult()        結果を回収し、このブラウザにログイン cookie を発行
//   --- 同一端末 (fragment) ---
//   /auth/callback/:C#id_token=… で開かれたブラウザに
//                                GET  /auth/callback/:C → ライブラリの着地ページ (HTML)。フラグメントを読んで
//   POST /api/login/exchange/:C -> auth.exchange(C)       検証して、このブラウザにログイン cookie を発行し、/ へ戻す
//
//   GET /api/me               -> cookie のセッションからログイン中ユーザーを返す
//   POST /api/logout          -> セッションの行を消す
//
// 応答方式 (QR か同一端末リンクか) を選ぶのはブラウザで、この Worker は知らない。状態は D1 だけ (worker/store.ts, worker/session.ts)。
// cookie を発行する status / exchange は JSON の POST だけを受ける。form を受けると cross-site の <form> で
// 他人の結果や ID Token を踏まされてその人としてログインしてしまう (login CSRF)。JSON は cross-site からは送れない
import { AuthError, ConcrntAuth, landingPage, parseAuthorizationResponse, type LoginResult } from '@concrnt/auth-client'
import { d1Store } from './store.js'
import { createSession, deleteSession, readCookie, readSession, SESSION_COOKIE, sessionCookie } from './session.js'

// Authenticator がブラウザ由来の fetch で来る場合 (world-app の webview 等) に必要
const CORS = { 'Access-Control-Allow-Origin': '*' }

const LANDING_TEXTS = { title: 'Concrnt でログイン', working: 'ログインしています…', denied: 'ログインが拒否されました', back: '戻る' }

export default {
    async fetch(request, env) {
        const url = new URL(request.url)
        // RP のオリジン (§5.1)。Authorization Request URI には host しか載らず https が暗黙なので、
        // ローカル開発 (http://localhost) では PUBLIC_ORIGIN で公開 URL を指定する
        const auth = new ConcrntAuth({
            origin: env.PUBLIC_ORIGIN || url.origin,
            store: d1Store(env.DB),
            clientMetadata: { client_name: 'Concrnt Login Sample' }
        })
        try {
            return await route(auth, request, url, env.DB)
        } catch (e) {
            // ライブラリの拒否 (不正な要求・ID Token 検証失敗・応答済みなど) はそのままステータスに写す
            if (e instanceof AuthError) return Response.json({ code: e.code, message: e.message }, { status: e.status, headers: CORS })
            throw e
        }
    }
} satisfies ExportedHandler<Env>

const route = async (auth: ConcrntAuth, request: Request, url: URL, db: D1Database): Promise<Response> => {
    const { method, pathname } = { method: request.method, pathname: url.pathname }

    // §5: 要求を発行する。応答方式は選ばない。start() の結果をそのままブラウザに返す
    if (method === 'POST' && pathname === '/api/login/start') return Response.json(await auth.start())

    // §5.3: request_uri。Authenticator が取りに来る
    if (method === 'GET' && pathname.startsWith(auth.requestPath + '/')) {
        return Response.json(await auth.getRequestObject(pathname.slice(auth.requestPath.length + 1)), { headers: CORS })
    }

    if (pathname.startsWith(auth.redirectPath + '/')) {
        const challenge = pathname.slice(auth.redirectPath.length + 1)
        // §8.1: redirect_uri に別端末の Authenticator が direct_post してくる。預かるだけで、送信者には何も発行しない
        if (method === 'POST') {
            await auth.receiveDirectPost(challenge, parseAuthorizationResponse(await request.formData()))
            return new Response(null, { status: 204, headers: CORS })
        }
        // §8.2: 同じ URL をアプリが #id_token=… 付きでブラウザに開く。着地ページがフラグメントを exchange に送る
        if (method === 'GET') return landingPage({ exchangeUrl: `/api/login/exchange/${challenge}`, callbackURL: '/', texts: LANDING_TEXTS })
    }

    // §8.2: 着地ページが、開かれた URL の C とフラグメントの内容を送ってくる。送ってきたブラウザにログイン cookie を発行する
    if (method === 'POST' && pathname.startsWith('/api/login/exchange/')) {
        const body = await jsonBody(request)
        if (!body) return unsupportedMediaType()
        return deliver(await auth.exchange(pathname.slice('/api/login/exchange/'.length), parseAuthorizationResponse(body)), db)
    }

    // §8.1: 開始したブラウザが pollToken (QR に載らない秘密) で結果を回収する。期限切れはブラウザが exp で判断する
    if (method === 'POST' && pathname === '/api/login/status') {
        const body = await jsonBody(request)
        if (!body) return unsupportedMediaType()
        if (typeof body.pollToken !== 'string') return Response.json({ code: 'bad_request', message: 'pollToken required' }, { status: 400 })
        const result = await auth.pollResult(body.pollToken)
        return result ? deliver(result, db) : Response.json({ status: 'pending' })
    }

    if (method === 'GET' && pathname === '/api/me') {
        const token = readCookie(request, SESSION_COOKIE)
        const user = token ? await readSession(db, token) : null
        return user ? Response.json(user) : Response.json({ code: 'unauthorized', message: 'not logged in' }, { status: 401 })
    }
    if (method === 'POST' && pathname === '/api/logout') {
        const token = readCookie(request, SESSION_COOKIE)
        if (token) await deleteSession(db, token)
        return new Response(null, { status: 204, headers: { 'Set-Cookie': sessionCookie(null) } })
    }
    return Response.json({ code: 'not_found', message: 'not found' }, { status: 404 })
}

// ログイン成立。以後は cookie のセッションでユーザーを識別する (ここが「セッションの確立」)
const deliver = async (result: LoginResult, db: D1Database): Promise<Response> => {
    if (result.status !== 'ok') return Response.json({ status: 'denied', callbackURL: '/' })
    const token = await createSession(db, result.claims)
    return Response.json({ status: 'ok', callbackURL: '/', user: await readSession(db, token) }, { headers: { 'Set-Cookie': sessionCookie(token) } })
}

/** JSON の body。Content-Type が JSON でなければ null (cross-site の form を弾く) */
const jsonBody = async (request: Request): Promise<Record<string, unknown> | null> => {
    if (!/^application\/json\b/i.test(request.headers.get('Content-Type') ?? '')) return null
    const body: unknown = await request.json().catch(() => null)
    return body && typeof body === 'object' ? (body as Record<string, unknown>) : {}
}

const unsupportedMediaType = (): Response => Response.json({ code: 'unsupported_media_type', message: 'application/json required' }, { status: 415 })
