import type { BetterAuthPluginDBSchema } from '@better-auth/core/db'

/**
 * ユーザーに紐付いた Concrnt のエンティティ (CCID)。パスキープラグインの `passkey` テーブルと同じ位置付けで、
 * 1 ユーザーに複数の CCID を登録できる。認証では `ccid` からユーザーを引く
 */
export const schema = {
    concrntIdentity: {
        fields: {
            userId: {
                type: 'string',
                required: true,
                references: { model: 'user', field: 'id', onDelete: 'cascade' },
                index: true
            },
            /** CIP-0 §5.2 の CCID (`con1…`)。ID Token の `sub` */
            ccid: { type: 'string', required: true, unique: true },
            /** ID Token の `concrnt_domain` (自己申告・最新の値)。表示や解決のヒント用で、信頼の根拠にはしない */
            domain: { type: 'string', required: false },
            /** 利用者が付けるラベル */
            name: { type: 'string', required: false },
            createdAt: { type: 'date', required: true },
            updatedAt: { type: 'date', required: true }
        }
    }
} satisfies BetterAuthPluginDBSchema

export interface ConcrntIdentity {
    id: string
    userId: string
    ccid: string
    domain?: string | null
    name?: string | null
    createdAt: Date
    updatedAt: Date
}
