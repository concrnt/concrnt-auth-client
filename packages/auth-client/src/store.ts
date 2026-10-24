/**
 * ConcrntAuth が要求の行と別端末フローの結果を置くストア。
 *
 * 行はどれも短命 (要求の有効期間 + 1 分) で、キーはランダムなので衝突しない。
 * 一回限り (§9 手順 3) は consume の原子性に依る: DB の `DELETE … RETURNING`、Redis の `GETDEL`、
 * better-auth の verification テーブル (`consumeVerificationValue`) などで実装する。
 * Cloudflare KV のように原子的な取り出しが無いストアでは、同じ要求への同時応答が両方通りうる
 */
export interface AuthStore {
    /** expiresAt (UNIX 秒) を過ぎたら消えてよい値を置く。同じキーへの 2 回目は上書きでよい */
    put(key: string, value: string, expiresAt: number): Promise<void>
    /** 期限内の値。無ければ null */
    get(key: string): Promise<string | null>
    /** 期限内の値を原子的に取り出して消す。無ければ null */
    consume(key: string): Promise<string | null>
}

/** 単一プロセス用の参照実装。テストやローカル開発向け */
export class MemoryStore implements AuthStore {
    private readonly entries = new Map<string, { value: string; expiresAt: number }>()
    private readonly now: () => number

    constructor(now: () => number = () => Date.now() / 1000) {
        this.now = now
    }

    async put(key: string, value: string, expiresAt: number): Promise<void> {
        this.entries.set(key, { value, expiresAt })
    }

    async get(key: string): Promise<string | null> {
        return this.read(key)
    }

    /** 同期的に読んで消すので、単一プロセス内では同時呼び出しのうち 1 つだけが値を得る */
    async consume(key: string): Promise<string | null> {
        const value = this.read(key)
        if (value !== null) this.entries.delete(key)
        return value
    }

    private read(key: string): string | null {
        const entry = this.entries.get(key)
        if (!entry) return null
        if (entry.expiresAt <= this.now()) {
            this.entries.delete(key)
            return null
        }
        return entry.value
    }

    /** テスト用: 期限内のキー一覧 */
    keys(): string[] {
        return [...this.entries.entries()].filter(([, e]) => e.expiresAt > this.now()).map(([k]) => k)
    }
}
