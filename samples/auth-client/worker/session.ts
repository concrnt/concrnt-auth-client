// ログイン成立後のセッション。この RP 固有の仕組みで CIP-17 の範囲外 (ライブラリは検証済みクレームを返すだけ)。
// ログイントークン L は HS256 JWT (typ: login+jwt) を cookie に載せ、サーバーには何も記録しない。
// §9: セッションは sub (CCID) に結び付ける。name / picture は Authenticator の自己申告で表示専用 (§7.3)
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import type { IdTokenClaims } from '@concrnt/auth-client'

export const LOGIN_TTL = 60 * 60 * 24 // ログイン済み cookie の有効期間 (秒)

interface LoginToken {
    sub: string
    iat: number
    exp: number
    concrnt_domain: string
    name?: string
    picture?: string
}

export interface LoginUser {
    ccid: string
    domain: string
    name?: string
    picture?: string
}

export const issueLoginToken = (claims: IdTokenClaims, secret: string): string => {
    const now = Math.floor(Date.now() / 1000)
    const login: LoginToken = {
        sub: claims.sub,
        iat: now,
        exp: now + LOGIN_TTL,
        concrnt_domain: claims.concrnt_domain,
        name: claims.name,
        picture: claims.picture
    }
    const header = b64url(utf8(JSON.stringify({ alg: 'HS256', typ: 'login+jwt' })))
    const body = b64url(utf8(JSON.stringify(login)))
    return `${header}.${body}.${b64url(hmac(sha256, utf8(secret), utf8(`${header}.${body}`)))}`
}

/** 署名・typ・exp を確認してユーザーを返す。失敗は throw */
export const readLoginToken = (token: string, secret: string): LoginUser => {
    const parts = token.split('.')
    if (parts.length !== 3) throw new Error('malformed token')
    const [headerB64, payloadB64, signatureB64] = parts as [string, string, string]
    const expected = b64url(hmac(sha256, utf8(secret), utf8(`${headerB64}.${payloadB64}`)))
    if (expected !== signatureB64) throw new Error('bad signature')
    const header = JSON.parse(atob(headerB64))
    if (header.alg !== 'HS256' || header.typ !== 'login+jwt') throw new Error('unexpected token type')
    const login = JSON.parse(new TextDecoder().decode(fromB64url(payloadB64))) as LoginToken
    if (typeof login.exp !== 'number' || login.exp <= Math.floor(Date.now() / 1000)) throw new Error('token expired')
    return { ccid: login.sub, domain: login.concrnt_domain, name: login.name, picture: login.picture }
}

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s)
const b64url = (bytes: Uint8Array): string =>
    btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
const fromB64url = (s: string): Uint8Array => Uint8Array.from(atob(s.replaceAll('-', '+').replaceAll('_', '/')), (c) => c.charCodeAt(0))
