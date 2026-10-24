// RP が自分で発行し、自分だけが検証するトークン。RP はこれらを保存しない。検証は MAC と exp だけで完結する。
//   チャレンジ C — バイナリ詰め (下記)。request_uri のパスと state に載せて Authenticator を経由し、応答と一緒に戻ってくる。
//                  QR に入るので短さが効く: 36 バイト → base64url 48 文字。応答方式 (§8) には依存しない
//   封筒 (HS256 JWT) — メールボックスに置く結果など。長さは問題にならないので読みやすさ優先
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { base64urlnopad } from '@scure/base'

// ---- チャレンジ C ----
// C = base64url( exp(4B, uint32 BE) || sh(16B) || mac(16B) )
//   sh:  SHA-256(session) の先頭 16 バイト (別端末フローでの結果の宛先)
//   mac: HMAC-SHA256(secret, 先頭 20 バイト) の先頭 16 バイト
const SIGNED_PREFIX_LENGTH = 4 + 16
const CHALLENGE_LENGTH = SIGNED_PREFIX_LENGTH + 16

export const SESSION_HASH_LENGTH = 16

export interface ChallengePayload {
    exp: number
    /** 16 バイト */
    sh: Uint8Array
}

export const packChallenge = ({ exp, sh }: ChallengePayload, secret: string): string => {
    if (sh.length !== SESSION_HASH_LENGTH) throw new Error('sh must be 16 bytes')
    const bytes = new Uint8Array(CHALLENGE_LENGTH)
    new DataView(bytes.buffer).setUint32(0, exp)
    bytes.set(sh, 4)
    bytes.set(hmac(sha256, utf8Bytes(secret), bytes.subarray(0, SIGNED_PREFIX_LENGTH)).subarray(0, 16), SIGNED_PREFIX_LENGTH)
    return base64urlEncode(bytes)
}

/** MAC (定数時間比較) と exp を確認してペイロードを返す。失敗は throw */
export const unpackChallenge = (challenge: string, secret: string, now: number): ChallengePayload => {
    let bytes: Uint8Array
    try {
        bytes = base64urlDecode(challenge)
    } catch {
        throw new Error('malformed challenge')
    }
    if (bytes.length !== CHALLENGE_LENGTH) throw new Error('malformed challenge')
    const expected = hmac(sha256, utf8Bytes(secret), bytes.subarray(0, SIGNED_PREFIX_LENGTH)).subarray(0, 16)
    if (!constantTimeEqual(expected, bytes.subarray(SIGNED_PREFIX_LENGTH))) throw new Error('bad mac')
    const exp = new DataView(bytes.buffer, bytes.byteOffset).getUint32(0)
    if (exp <= now) throw new Error('challenge expired')
    return { exp, sh: bytes.slice(4, SIGNED_PREFIX_LENGTH) }
}

// ---- HS256 JWT (メールボックスの封筒など) ----
export const signJwt = (typ: string, payload: object, secret: string): string => {
    const header = base64urlEncode(utf8Bytes(JSON.stringify({ alg: 'HS256', typ })))
    const body = base64urlEncode(utf8Bytes(JSON.stringify(payload)))
    const signature = hmac(sha256, utf8Bytes(secret), utf8Bytes(`${header}.${body}`))
    return `${header}.${body}.${base64urlEncode(signature)}`
}

/** 署名・typ・exp を確認してペイロードを返す。失敗は throw */
export const verifyJwt = <T extends { exp: number }>(token: string, typ: string, secret: string, now: number): T => {
    const parts = token.split('.')
    if (parts.length !== 3) throw new Error('malformed token')
    const [headerB64, payloadB64, signatureB64] = parts as [string, string, string]

    const expected = hmac(sha256, utf8Bytes(secret), utf8Bytes(`${headerB64}.${payloadB64}`))
    if (!constantTimeEqual(expected, base64urlDecode(signatureB64))) throw new Error('bad signature')

    const header = JSON.parse(utf8String(base64urlDecode(headerB64)))
    if (header.alg !== 'HS256' || header.typ !== typ) throw new Error('unexpected token type')

    const payload = JSON.parse(utf8String(base64urlDecode(payloadB64))) as T
    if (typeof payload.exp !== 'number' || payload.exp <= now) throw new Error('token expired')
    return payload
}

/** 秘密鍵で値を導出する (nonce など)。保存せずに同じ入力から同じ値を再計算するために使う */
export const derive = (label: string, input: string, secret: string): string =>
    base64urlEncode(hmac(sha256, utf8Bytes(secret), utf8Bytes(`${label}:${input}`)))

/** 推測困難なランダム値 (32 バイト) */
export const randomToken = (): string => base64urlEncode(crypto.getRandomValues(new Uint8Array(32)))

/** session のハッシュ。要求トークンに入れて公開しても session 自体は分からない。16 バイトに詰めて QR を小さく保つ */
export const sessionHash = (session: string): Uint8Array => sha256(utf8Bytes(session)).slice(0, SESSION_HASH_LENGTH)

export const base64urlEncode = (bytes: Uint8Array): string => base64urlnopad.encode(bytes)
export const base64urlDecode = (input: string): Uint8Array => base64urlnopad.decode(input)

export const constantTimeEqual = (a: Uint8Array, b: Uint8Array): boolean => {
    if (a.length !== b.length) return false
    let diff = 0
    for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
    return diff === 0
}

export const utf8Bytes = (s: string): Uint8Array => new TextEncoder().encode(s)
export const utf8String = (bytes: Uint8Array): string => new TextDecoder().decode(bytes)
