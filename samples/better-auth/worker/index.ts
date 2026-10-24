// CIP-17 (Sign-In with Concrnt) を better-auth で使う RP のサンプル Worker。
// ルーティングは better-auth に丸ごと任せる: /api/auth/* を auth.handler に渡すだけで、
// @concrnt/better-auth が /api/auth/concrnt/* (開始・request_uri・redirect_uri・status・exchange・identity 管理) を生やす。
// それ以外のパスは静的アセット (SPA) に落ちる
import { createAuth } from './auth.js'

export default {
    async fetch(request, env) {
        const url = new URL(request.url)
        if (!url.pathname.startsWith('/api/auth/')) return new Response(null, { status: 404 })
        // RP のオリジン (§5.1)。ローカル開発 (http://localhost) では PUBLIC_ORIGIN で公開 URL を指定する
        const origin = env.PUBLIC_ORIGIN || url.origin
        try {
            return await createAuth(env, origin, url.hostname).handler(request)
        } catch (e) {
            return new Response(e instanceof Error ? e.message : 'error', { status: 500 })
        }
    }
} satisfies ExportedHandler<Env>
