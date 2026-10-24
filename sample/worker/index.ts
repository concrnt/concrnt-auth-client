// CIP-17 (Sign-In with Concrnt) の RP (Relying Party) 側サンプル。プロトコル処理は @concrnt/auth-client に任せ、
// ここにはルーティングとログイン後のセッション (worker/session.ts) だけがある。
//
//   ブラウザ (src/App.tsx)        この Worker                              Authenticator (world-app)
//   ---------------------        -----------                              -------------------------
//   POST /api/login/start -----> auth.start()             チャレンジ C と request_uri を返す。何も保存しない
//   request_uri を concrnt-auth://<mode>/… にして QR / リンクに
//                                                         <-QR/link-- GET  /auth/request/:C  → auth.getRequestObject(C)
//   --- 別端末 (direct_post) ---
//                                                         <----------- POST /auth/callback/:C → auth.receiveDirectPost(C) → mailbox
//   GET /api/login/status -----> auth.pollResult()        mailbox から結果を回収し、ログイン cookie を発行
//   --- 同一端末 (fragment) ---
//   /auth/callback/:C#id_token=… で開かれたブラウザが
//   POST /api/login/session/:C -> auth.exchange(C)        検証して、このブラウザにログイン cookie を発行
//
// redirect_uri は要求ごとに異なり (末尾が C)、応答がどの要求のものかは届いた URL で決まる
//
//   GET /api/me               -> cookie (ログイントークン L) からログイン中ユーザーを返す
//
// 応答方式 (QR か同一端末リンクか) を選ぶのはブラウザで、この Worker は知らない。
// 残る状態は 2 つだけ:
//   LOGIN_SECRET — ライブラリのトークン署名と L の署名に使う HMAC 鍵
//   LOGIN_KV     — ライブラリの AuthStore (別端末フローのメールボックスと、応答済みチャレンジの記録)
import { AuthError, ConcrntAuth, parseAuthorizationResponse, type LoginResult } from '@concrnt/auth-client'
import { kvStore } from './store.js'
import { issueLoginToken, readLoginToken, LOGIN_TTL } from './session.js'

// Authenticator がブラウザ由来の fetch で来る場合 (world-app の webview 等) に必要
const CORS = { 'Access-Control-Allow-Origin': '*' }

export default {
    async fetch(request, env) {
        const url = new URL(request.url)
        const secret = resolveSecret(env, url)
        if (!secret) return new Response('LOGIN_SECRET is not configured', { status: 500 })

        // RP のオリジン (§5.1)。Authorization Request URI には host しか載らず https が暗黙なので、
        // ローカル開発 (http://localhost) では PUBLIC_ORIGIN で公開 URL を指定する
        const auth = new ConcrntAuth({
            origin: env.PUBLIC_ORIGIN || url.origin,
            secret,
            store: kvStore(env.LOGIN_KV),
            clientMetadata: { client_name: 'Concrnt Login Sample' }
        })

        try {
            return await route(auth, request, url, secret)
        } catch (e) {
            // ライブラリの拒否 (不正な要求・ID Token 検証失敗・応答済みチャレンジなど) はそのままステータスに写す
            if (e instanceof AuthError) return new Response(e.message, { status: e.status, headers: CORS })
            throw e
        }
    }
} satisfies ExportedHandler<Env>

const route = async (auth: ConcrntAuth, request: Request, url: URL, secret: string): Promise<Response> => {
    // §5: 要求を発行する。応答方式は選ばない。ブラウザが requestUri から QR 用 / リンク用の URI を組む
    if (request.method === 'POST' && url.pathname === '/api/login/start') return Response.json(auth.start())

    // §5.3: request_uri。Authenticator が取りに来る
    if (request.method === 'GET' && url.pathname.startsWith(auth.requestPath + '/')) {
        return Response.json(auth.getRequestObject(url.pathname.slice(auth.requestPath.length + 1)), { headers: CORS })
    }

    // §8.1: redirect_uri (= /auth/callback/<C>)。別端末の Authenticator が direct_post してくる。預かるだけで、送信者には何も発行しない
    if (request.method === 'POST' && url.pathname.startsWith(auth.redirectPath + '/')) {
        const challenge = url.pathname.slice(auth.redirectPath.length + 1)
        await auth.receiveDirectPost(challenge, parseAuthorizationResponse(await request.formData()))
        return new Response(null, { status: 204, headers: CORS })
    }

    // §8.1: 開始したブラウザが session (QR に載らない秘密) で結果を回収する。期限切れはブラウザが exp で判断する
    if (request.method === 'GET' && url.pathname === '/api/login/status') {
        const session = url.searchParams.get('session')
        if (!session) return new Response('session required', { status: 400 })
        const result = await auth.pollResult(session)
        return result ? deliver(result, secret) : Response.json({ status: 'pending' })
    }

    // §8.2: redirect_uri#id_token=… で開かれたブラウザが、開かれた URL の C とフラグメントの内容をそのまま送ってくる。
    // 送ってきたブラウザにログイン cookie を発行する
    if (request.method === 'POST' && url.pathname.startsWith('/api/login/session/')) {
        const challenge = url.pathname.slice('/api/login/session/'.length)
        return deliver(await auth.exchange(challenge, parseAuthorizationResponse(await request.formData())), secret)
    }

    if (request.method === 'GET' && url.pathname === '/api/me') return me(request, secret)
    if (request.method === 'POST' && url.pathname === '/api/logout') return logout()
    return new Response(null, { status: 404 })
}

// ログイン成立。以後は cookie のログイントークン L でユーザーを識別する (ここが「セッションの確立」)
const deliver = (result: LoginResult, secret: string): Response => {
    if (result.status !== 'ok') return Response.json({ status: result.status })
    const token = issueLoginToken(result.claims, secret)
    return Response.json(
        { status: 'ok', user: readLoginToken(token, secret) },
        { headers: { 'Set-Cookie': `sid=${token}; Path=/; Max-Age=${LOGIN_TTL}; HttpOnly; Secure; SameSite=Lax` } }
    )
}

const me = (request: Request, secret: string): Response => {
    const sid = readCookie(request, 'sid')
    try {
        if (!sid) throw new Error('no cookie')
        return Response.json(readLoginToken(sid, secret))
    } catch {
        return new Response('not logged in', { status: 401 })
    }
}

// L はサーバーに記録していないので失効はできない。cookie を消すだけ
const logout = (): Response =>
    new Response(null, { status: 204, headers: { 'Set-Cookie': 'sid=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax' } })

// 署名鍵。本番では `wrangler secret put LOGIN_SECRET`、ローカルでは .dev.vars で与える。
// localhost だけは未設定でも動くように固定値を使う (公開 URL では拒否する)
const resolveSecret = (env: Env, url: URL): string | null => {
    if (env.LOGIN_SECRET) return env.LOGIN_SECRET
    if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') return 'insecure-dev-secret-for-localhost-only'
    return null
}

const readCookie = (request: Request, name: string): string | null => {
    for (const part of request.headers.get('Cookie')?.split(';') ?? []) {
        const [k, v] = part.trim().split('=')
        if (k === name) return v ?? null
    }
    return null
}
