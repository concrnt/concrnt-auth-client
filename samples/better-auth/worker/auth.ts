// better-auth の組み立て。CIP-17 (Sign-In with Concrnt) は @concrnt/better-auth の concrnt() を差し込むだけ。
// DB は D1 (SQLite) で、スキーマは migrations/ を wrangler で適用する
import { betterAuth } from 'better-auth'
import { D1Dialect } from 'kysely-d1'
import { concrnt } from '@concrnt/better-auth'

/** origin は RP のオリジン (PUBLIC_ORIGIN か要求のオリジン)。requestHost は secret 未設定時に localhost だけ開発用鍵を許すための判定に使う */
export const createAuth = (env: Env, origin: string, requestHost: string) =>
    betterAuth({
        appName: 'Concrnt × better-auth Sample',
        database: { dialect: new D1Dialect({ database: env.DB }), type: 'sqlite' },
        baseURL: origin,
        basePath: '/api/auth',
        secret: resolveSecret(env, requestHost),
        // メール/パスワードは使わない。ログイン手段は Concrnt だけ
        emailAndPassword: { enabled: false },
        advanced: {
            // スキーマは wrangler d1 migrations で適用済みなので、リクエストごとの照合は省く
            database: { validateSchema: false }
        },
        // 未登録の CCID はそのままサインアップになる (disableSignUp: true で既存ユーザーだけに限定できる)
        plugins: [concrnt()]
    })

export type Auth = ReturnType<typeof createAuth>

// 署名鍵。本番では `wrangler secret put BETTER_AUTH_SECRET`、ローカルでは .dev.vars で与える。
// localhost だけは未設定でも動くように固定値を使う (公開 URL では拒否する)
const resolveSecret = (env: Env, requestHost: string): string => {
    if (env.BETTER_AUTH_SECRET) return env.BETTER_AUTH_SECRET
    if (requestHost === 'localhost' || requestHost === '127.0.0.1') return 'insecure-dev-secret-for-localhost-only-0123456789'
    throw new Error('BETTER_AUTH_SECRET is not configured')
}
