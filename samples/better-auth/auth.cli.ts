// `better-auth generate` 用の設定。D1 は Node から触れないので、同じ SQLite 方言の node:sqlite に向けて SQL を出す。
// 出力 (migrations/0001_init.sql) を `wrangler d1 migrations apply` で D1 に適用する
import { DatabaseSync } from 'node:sqlite'
import { betterAuth } from 'better-auth'
import { concrnt } from '@concrnt/better-auth'

export const auth = betterAuth({
    database: new DatabaseSync(':memory:'),
    emailAndPassword: { enabled: false },
    plugins: [concrnt()]
})
