import type { AuthStore } from '@concrnt/auth-client'
import type { InternalAdapter } from '@better-auth/core'

/**
 * @concrnt/auth-client の AuthStore を better-auth の verification テーブルに写す。
 * 利用側に別のストアを用意させないための層で、メールボックス (§8.1) と使用済み記録 (§9 手順 3) がここに入る。
 * 使用済み記録は reserveVerificationValue (主キー衝突による first-writer-wins) で原子的に行う
 */
export const verificationStore = (adapter: InternalAdapter): AuthStore => ({
    get: async (key) => (await adapter.findVerificationValue(key))?.value ?? null,
    set: async (key, value, ttlSeconds) => {
        await adapter.createVerificationValue({ identifier: key, value, expiresAt: expiresIn(ttlSeconds) })
    },
    delete: async (key) => {
        await adapter.deleteVerificationByIdentifier(key)
    },
    setIfAbsent: (key, value, ttlSeconds) => adapter.reserveVerificationValue({ identifier: key, value, expiresAt: expiresIn(ttlSeconds) })
})

const expiresIn = (ttlSeconds: number): Date => new Date(Date.now() + ttlSeconds * 1000)
