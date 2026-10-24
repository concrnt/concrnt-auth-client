/**
 * 別端末フロー (§8.1) で Authenticator からの応答をブラウザに渡すメールボックス。
 *
 * 置く値はライブラリが署名した封筒で、読み戻すときに署名と宛先を照合するので、
 * ストアに改ざん耐性や強整合は要らない。可用性と TTL (または期限切れを無視できること) だけあればよい。
 * Cloudflare KV / Redis / Postgres / メモリなど、get・set・delete があれば何でも注入できる。
 */
export interface AuthStore {
    get(key: string): Promise<string | null>
    /** ttlSeconds を過ぎた値は返さなくてよい (返しても封筒の exp で捨てられる) */
    set(key: string, value: string, ttlSeconds: number): Promise<void>
    delete(key: string): Promise<void>
}

/** 単一プロセス用の参照実装。テストやローカル開発向け */
export class MemoryStore implements AuthStore {
    private readonly entries = new Map<string, { value: string; expiresAt: number }>()
    private readonly now: () => number

    constructor(now: () => number = () => Date.now() / 1000) {
        this.now = now
    }

    async get(key: string): Promise<string | null> {
        const entry = this.entries.get(key)
        if (!entry) return null
        if (entry.expiresAt <= this.now()) {
            this.entries.delete(key)
            return null
        }
        return entry.value
    }

    async set(key: string, value: string, ttlSeconds: number): Promise<void> {
        this.entries.set(key, { value, expiresAt: this.now() + ttlSeconds })
    }

    async delete(key: string): Promise<void> {
        this.entries.delete(key)
    }
}
