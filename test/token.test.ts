import { describe, expect, it } from 'vitest'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { packChallenge, unpackChallenge, sessionHash, signJwt, verifyJwt, base64urlDecode, base64urlEncode } from '../src/token.js'

const secret = 'test-secret'
const now = 1_800_000_000
const sh = sessionHash('some-session')

describe('challenge C', () => {
    it('round-trips and is 48 chars (36 bytes)', () => {
        const c = packChallenge({ exp: now + 300, sh }, secret)
        expect(c).toHaveLength(48)
        expect(base64urlDecode(c)).toHaveLength(36)
        const payload = unpackChallenge(c, secret, now)
        expect(payload.exp).toBe(now + 300)
        expect(payload.sh).toEqual(sh)
    })

    it('rejects a tampered middle character (bad mac)', () => {
        const c = packChallenge({ exp: now + 300, sh }, secret)
        const i = 20
        const tampered = c.slice(0, i) + (c[i] === 'A' ? 'B' : 'A') + c.slice(i + 1)
        expect(() => unpackChallenge(tampered, secret, now)).toThrow('bad mac')
    })

    it('rejects a different secret', () => {
        const c = packChallenge({ exp: now + 300, sh }, secret)
        expect(() => unpackChallenge(c, 'other', now)).toThrow('bad mac')
    })

    it('rejects expired, malformed and wrong-length challenges', () => {
        const c = packChallenge({ exp: now + 300, sh }, secret)
        expect(() => unpackChallenge(c, secret, now + 300)).toThrow('challenge expired')
        expect(() => unpackChallenge('!!not-base64!!', secret, now)).toThrow('malformed challenge')
        expect(() => unpackChallenge(c.slice(0, 40), secret, now)).toThrow('malformed challenge')
    })

    it('mac covers exp (a valid mac from another exp is rejected)', () => {
        const bytes = base64urlDecode(packChallenge({ exp: now + 300, sh }, secret))
        new DataView(bytes.buffer, bytes.byteOffset).setUint32(0, now + 3000)
        expect(() => unpackChallenge(base64urlEncode(bytes), secret, now)).toThrow('bad mac')
        // 正しく MAC を付け直せば通る (形式の確認)
        bytes.set(hmac(sha256, new TextEncoder().encode(secret), bytes.subarray(0, 20)).subarray(0, 16), 20)
        expect(unpackChallenge(base64urlEncode(bytes), secret, now).exp).toBe(now + 3000)
    })
})

describe('HS256 envelope', () => {
    it('round-trips and checks typ, signature and exp', () => {
        const token = signJwt('x+jwt', { a: 1, exp: now + 10 }, secret)
        expect(verifyJwt<{ a: number; exp: number }>(token, 'x+jwt', secret, now).a).toBe(1)
        expect(() => verifyJwt(token, 'y+jwt', secret, now)).toThrow('unexpected token type')
        expect(() => verifyJwt(token, 'x+jwt', 'other', now)).toThrow('bad signature')
        expect(() => verifyJwt(token, 'x+jwt', secret, now + 10)).toThrow('token expired')
    })
})
