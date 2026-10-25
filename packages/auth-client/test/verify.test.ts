import { describe, expect, it } from 'vitest'
import { peekIdTokenNonce, verifyIdToken } from '../src/verify.js'
import { issueIdToken, makeIdentity } from './authenticator.js'

const audience = 'https://rp.example/auth/callback'
const now = 1_800_000_000
const identity = makeIdentity()
const request = { nonce: 'n-abc', audience }
const verify = (token: string) => verifyIdToken(token, { audience, nonce: request.nonce, now })

describe('verifyIdToken (§9)', () => {
    it('accepts a valid token and returns the claims', () => {
        const claims = verify(issueIdToken(identity, request, now))
        expect(claims.sub).toBe(identity.ccid)
        expect(claims.sub).toMatch(/^con1[a-z0-9]{38}$/)
        expect(claims.aud).toBe(audience)
        expect(claims.name).toBe('Test User')
    })

    it('accepts v = 27/28 (normalized)', () => {
        const token = issueIdToken(identity, request, now, { mutateSignature: (sig) => (sig[64]! += 27) })
        expect(verify(token).sub).toBe(identity.ccid)
    })

    it('tolerates clock skew in both directions', () => {
        // 発行から 299 秒 + 許容 300 秒 → まだ有効
        expect(verify(issueIdToken(identity, request, now - 599)).sub).toBe(identity.ccid)
        // 未来の iat も許容幅内なら受理
        expect(verify(issueIdToken(identity, request, now + 300)).sub).toBe(identity.ccid)
    })

    it.each([
        ['alg', { header: { alg: 'HS256' } }, 'alg must be CONCRNT'],
        ['typ', { header: { typ: 'at+jwt' } }, 'typ must be JWT'],
        ['kid (subkey)', { header: { kid: 'cckv://con1x/keys/cck1y' } }, 'kid is not allowed'],
        ['aud (other host)', { claims: { aud: 'https://evil.example/auth/callback' } }, 'aud mismatch'],
        ['aud (origin only)', { claims: { aud: 'https://rp.example' } }, 'aud mismatch'],
        ['aud with trailing slash', { claims: { aud: audience + '/' } }, 'aud mismatch'],
        ['aud via open redirector', { claims: { aud: 'https://rp.example/redirect?to=/auth/callback' } }, 'aud mismatch'],
        ['nonce', { claims: { nonce: 'x' } }, 'nonce mismatch'],
        ['sub=concrnt (CIP-2 auth token)', { claims: { sub: 'concrnt' } }, 'sub must equal iss'],
        ['sub not CCID', { claims: { sub: 'CON1ABC', iss: 'CON1ABC' } }, 'sub is not a CCID'],
        ['exp != iat + 300 (shorter)', { claims: { exp: now + 299 } }, 'exp must be iat + 300'],
        ['exp != iat + 300 (longer)', { claims: { exp: now + 600 } }, 'exp must be iat + 300'],
        ['expired beyond skew', { claims: { iat: now - 601, exp: now - 301 } }, 'token expired'],
        ['expired exactly at skew', { claims: { iat: now - 600, exp: now - 300 } }, 'token expired'],
        ['iat in the future', { claims: { iat: now + 301, exp: now + 601 } }, 'iat in the future'],
        ['iat string', { claims: { iat: String(now) } }, 'iat and exp must be numbers'],
        ['exp string', { claims: { exp: String(now + 300) } }, 'iat and exp must be numbers'],
        ['bad signature', { mutateSignature: (sig: Uint8Array) => (sig[10]! ^= 0xff) }, /signature does not match sub|invalid|curve|point|recover/i],
        ['bad recovery id', { mutateSignature: (sig: Uint8Array) => (sig[64] = 5) }, 'invalid recovery id']
    ])('rejects %s', (_name, overrides, message) => {
        expect(() => verify(issueIdToken(identity, request, now, overrides))).toThrow(message)
    })

    it('rejects a token signed by another key claiming this sub', () => {
        const other = makeIdentity()
        const token = issueIdToken(other, request, now, { claims: { iss: identity.ccid, sub: identity.ccid } })
        expect(() => verify(token)).toThrow('signature does not match sub')
    })

    it('rejects malformed JWTs and padded base64', () => {
        expect(() => verify('a.b')).toThrow('malformed JWT')
        const token = issueIdToken(identity, request, now)
        expect(() => verify(token + '=')).toThrow('base64url must not be padded')
    })
})

describe('peekIdTokenNonce (§9 step 2)', () => {
    it('reads the nonce from the payload without verifying anything', () => {
        expect(peekIdTokenNonce(issueIdToken(identity, request, now))).toBe('n-abc')
        // 署名が壊れていても読める (検証は行を引いた後)
        expect(peekIdTokenNonce(issueIdToken(identity, request, now, { mutateSignature: (s) => (s[0] ^= 1) }))).toBe('n-abc')
    })

    it('returns null for anything that is not a JWT with a string nonce', () => {
        expect(peekIdTokenNonce('a.b')).toBeNull()
        expect(peekIdTokenNonce('a.b.c.d')).toBeNull()
        expect(peekIdTokenNonce('not.a.jwt')).toBeNull()
        const [h, p, sig] = issueIdToken(identity, request, now).split('.')
        expect(peekIdTokenNonce(`${h}.${p}=.${sig}`)).toBeNull() // payload のパディングは拒否
        expect(peekIdTokenNonce(issueIdToken(identity, request, now, { claims: { nonce: 42 } }))).toBeNull()
        expect(peekIdTokenNonce(issueIdToken(identity, request, now, { claims: { nonce: '' } }))).toBeNull()
    })
})
