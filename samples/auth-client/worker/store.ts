// @concrnt/auth-client の AuthStore を Cloudflare D1 (SQLite) で実装する。
// consume は DELETE … RETURNING で原子的に行うので、同じ要求への同時応答は 1 件しか通らない (§9 手順 3)。
// D1 に TTL は無いので、書くたびに期限切れの行を掃除する
import type { AuthStore } from '@concrnt/auth-client'

export const d1Store = (db: D1Database): AuthStore => ({
    put: async (key, value, expiresAt) => {
        await db.batch([
            db.prepare('DELETE FROM login_store WHERE expires_at <= ?').bind(nowSeconds()),
            db.prepare('INSERT OR REPLACE INTO login_store (key, value, expires_at) VALUES (?, ?, ?)').bind(key, value, expiresAt)
        ])
    },
    get: async (key) => {
        const row = await db.prepare('SELECT value FROM login_store WHERE key = ? AND expires_at > ?').bind(key, nowSeconds()).first<{ value: string }>()
        return row?.value ?? null
    },
    consume: async (key) => {
        const row = await db.prepare('DELETE FROM login_store WHERE key = ? AND expires_at > ? RETURNING value').bind(key, nowSeconds()).first<{ value: string }>()
        return row?.value ?? null
    }
})

const nowSeconds = (): number => Math.floor(Date.now() / 1000)
