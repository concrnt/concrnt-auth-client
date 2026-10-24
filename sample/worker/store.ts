// @concrnt/auth-client の AuthStore を Cloudflare Workers KV で実装する。
// メールボックスの中身はライブラリが署名した封筒なので、KV の結果整合で十分
import type { AuthStore } from '@concrnt/auth-client'

export const kvStore = (kv: KVNamespace): AuthStore => ({
    get: (key) => kv.get(key),
    set: (key, value, ttlSeconds) => kv.put(key, value, { expirationTtl: Math.max(60, ttlSeconds) }), // KV の TTL 下限は 60 秒
    delete: (key) => kv.delete(key)
})
