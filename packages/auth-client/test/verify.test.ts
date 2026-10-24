import { describe, expect, it } from 'vitest'
import { verifyIdToken } from '../src/verify.js'
import { issueIdToken, makeIdentity } from './authenticator.js'
import type { RequestObject } from '../src/types.js'

const origin = 'https://rp.example'
const now = 1_800_000_000
const identity = makeIdentity()
const request = { nonce: 'n-abc' } as RequestObject
const verify = (token: string) => verifyIdToken(token, { origin, nonce: request.nonce, now })

describe('verifyIdToken (§9)', () => {
    it('accepts a valid token and returns the claims', () => {
        const claims = verify(issueIdToken(identity, request, origin, now))
        expect(claims.sub).toBe(identity.ccid)
        expect(claims.sub).toMatch(/^con1[a-z0-9]{38}$/)
        expect(claims.name).toBe('Test User')
    })

    it('accepts v = 27/28 (normalized)', () => {
        const token = issueIdToken(identity, request, origin, now, { mutateSignature: (sig) => (sig[64]! += 27) })
        expect(verify(token).sub).toBe(identity.ccid)
    })

    it.each([
        ['alg', { header: { alg: 'HS256' } }, 'alg must be CONCRNT'],
        ['typ', { header: { typ: 'at+jwt' } }, 'typ must be JWT'],
        ['kid (subkey)', { header: { kid: 'cckv://con1x/keys/cck1y' } }, 'kid is not allowed'],
        ['aud', { claims: { aud: 'https://evil.example' } }, 'aud mismatch'],
        ['aud with trailing slash', { claims: { aud: origin + '/' } }, 'aud mismatch'],
        ['nonce', { claims: { nonce: 'x' } }, 'nonce mismatch'],
        ['sub=concrnt (CIP-2 auth token)', { claims: { sub: 'concrnt' } }, 'sub must equal iss'],
        ['sub not CCID', { claims: { sub: 'CON1ABC', iss: 'CON1ABC' } }, 'sub is not a CCID'],
        ['expired', { claims: { exp: now - 1 } }, 'token expired'],
        ['iat string', { claims: { iat: String(now) } }, 'iat out of range'],
        ['iat too far', { claims: { iat: now - 1000 } }, 'iat out of range'],
        ['bad signature', { mutateSignature: (sig: Uint8Array) => (sig[10]! ^= 0xff) }, /signature does not match sub|invalid|curve|point|recover/i],
        ['bad recovery id', { mutateSignature: (sig: Uint8Array) => (sig[64] = 5) }, 'invalid recovery id']
    ])('rejects %s', (_name, overrides, message) => {
        expect(() => verify(issueIdToken(identity, request, origin, now, overrides))).toThrow(message)
    })

    it('rejects a token signed by another key claiming this sub', () => {
        const other = makeIdentity()
        const token = issueIdToken(other, request, origin, now, { claims: { iss: identity.ccid, sub: identity.ccid } })
        expect(() => verify(token)).toThrow('signature does not match sub')
    })

    it('rejects malformed JWTs and padded base64', () => {
        expect(() => verify('a.b')).toThrow('malformed JWT')
        const token = issueIdToken(identity, request, origin, now)
        expect(() => verify(token + '=')).toThrow('base64url must not be padded')
    })
})
