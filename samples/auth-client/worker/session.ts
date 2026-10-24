// ログイン成立後のセッション。この RP 固有の仕組みで CIP-17 の範囲外 (ライブラリは検証済みクレームを返すだけ)。
// ランダムなトークンを cookie に載せ、行を D1 に置く。ログアウトは行を消すだけで失効する。
// §9: セッションは sub (CCID) に結び付ける。name / picture は Authenticator の自己申告で表示専用 (§7.3)
import type { IdTokenClaims } from '@concrnt/auth-client'

export const SESSION_TTL = 60 * 60 * 24 // 秒
export const SESSION_COOKIE = 'sid'

export interface LoginUser {
    ccid: string
    domain: string
    name?: string
    picture?: string
}

/** セッションを作り、cookie に載せるトークンを返す */
export const createSession = async (db: D1Database, claims: IdTokenClaims): Promise<string> => {
    const token = base64url(crypto.getRandomValues(new Uint8Array(32)))
    const now = Math.floor(Date.now() / 1000)
    await db.batch([
        db.prepare('DELETE FROM login_session WHERE expires_at <= ?').bind(now),
        db
            .prepare('INSERT INTO login_session (token, ccid, domain, name, picture, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
            .bind(token, claims.sub, claims.concrnt_domain, claims.name ?? null, claims.picture ?? null, now + SESSION_TTL)
    ])
    return token
}

/** 期限内のセッションのユーザー。無ければ null */
export const readSession = async (db: D1Database, token: string): Promise<LoginUser | null> => {
    const row = await db
        .prepare('SELECT ccid, domain, name, picture FROM login_session WHERE token = ? AND expires_at > ?')
        .bind(token, Math.floor(Date.now() / 1000))
        .first<{ ccid: string; domain: string; name: string | null; picture: string | null }>()
    if (!row) return null
    return { ccid: row.ccid, domain: row.domain, name: row.name ?? undefined, picture: row.picture ?? undefined }
}

export const deleteSession = async (db: D1Database, token: string): Promise<void> => {
    await db.prepare('DELETE FROM login_session WHERE token = ?').bind(token).run()
}

export const sessionCookie = (token: string | null): string =>
    token === null
        ? `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`
        : `${SESSION_COOKIE}=${token}; Path=/; Max-Age=${SESSION_TTL}; HttpOnly; Secure; SameSite=Lax`

export const readCookie = (request: Request, name: string): string | null => {
    for (const part of request.headers.get('Cookie')?.split(';') ?? []) {
        const [k, v] = part.trim().split('=')
        if (k === name) return v ?? null
    }
    return null
}

const base64url = (bytes: Uint8Array): string => btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
