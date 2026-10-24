import { beforeEach, describe, expect, it } from 'vitest'
import { ConcrntAuth, authorizationRequestUri, parseAuthorizationResponse } from '../src/core.js'
import { AuthError } from '../src/errors.js'
import { MemoryStore } from '../src/store.js'
import { issueIdToken, makeIdentity } from './authenticator.js'

const origin = 'https://login-sample.test'
const secret = 'test-secret'
let clock = 1_800_000_000
const now = () => clock
const identity = makeIdentity()

let store: MemoryStore
let auth: ConcrntAuth

beforeEach(() => {
    clock = 1_800_000_000
    store = new MemoryStore(now)
    auth = new ConcrntAuth({ origin, secret, store, now, clientMetadata: { client_name: 'Test RP' } })
})

const storeKeys = () => [...(store as unknown as { entries: Map<string, { value: string }> }).entries.keys()]

describe('constructor', () => {
    it('rejects non-https origins except localhost, paths and trailing slashes', () => {
        expect(() => new ConcrntAuth({ origin: 'http://example.com', secret, store })).toThrow(AuthError)
        expect(() => new ConcrntAuth({ origin: 'https://example.com/', secret, store })).toThrow('without path')
        expect(() => new ConcrntAuth({ origin: 'https://example.com/app', secret, store })).toThrow('without path')
        expect(() => new ConcrntAuth({ origin: 'not a url', secret, store })).toThrow('not a URL')
        expect(() => new ConcrntAuth({ origin, secret: '', store })).toThrow('secret is required')
        expect(() => new ConcrntAuth({ origin, secret, store, requestPath: 'auth' })).toThrow('requestPath')
        expect(new ConcrntAuth({ origin: 'http://localhost:5173', secret, store }).origin).toBe('http://localhost:5173')
        expect(new ConcrntAuth({ origin: 'https://rp.example:8443', secret, store }).redirectUriFor('C')).toBe('https://rp.example:8443/auth/callback/C')
    })
})

describe('start / authorizationRequestUri / getRequestObject', () => {
    it('issues a mode-agnostic challenge and request_uri; the browser picks the mode', () => {
        const started = auth.start()
        expect(started.exp).toBe(clock + 300)
        expect(started.displayCode).toMatch(/\p{Extended_Pictographic}/u)
        expect(started.challenge).toHaveLength(48)
        expect(started.requestId).toHaveLength(22)
        expect(auth.requestIdOf(started.challenge)).toBe(started.requestId)
        expect(auth.requestIdOfSession(started.session)).toBe(started.requestId)
        expect(() => auth.requestIdOf(started.challenge.slice(1))).toThrow(AuthError)
        expect(started.requestUri).toBe(`https://login-sample.test/auth/request/${started.challenge}`)
        expect(authorizationRequestUri(started.requestUri, 'direct_post')).toBe(
            `concrnt-auth://direct_post/login-sample.test/auth/request/${started.challenge}`
        )
        const fr = authorizationRequestUri(started.requestUri, 'fragment')
        expect(fr).toBe(`concrnt-auth://fragment/login-sample.test/auth/request/${started.challenge}`)
        expect(fr.length).toBeLessThanOrEqual(110)
        expect(fr).not.toMatch(/[?#%]/)
        expect(storeKeys()).toEqual([]) // 何も保存しない
    })

    it('authorizationRequestUri rejects unknown modes and non-https request_uri', () => {
        expect(() => authorizationRequestUri('https://x.example/a', 'query' as never)).toThrow('unknown response_mode')
        expect(() => authorizationRequestUri('http://x.example/a', 'fragment')).toThrow('must be https')
    })

    it('rebuilds the same Request Object from C regardless of mode, with display_code always present', () => {
        const started = auth.start()
        const ro = auth.getRequestObject(started.challenge)
        expect(ro).toEqual({
            redirect_uri: `${origin}/auth/callback/${started.challenge}`,
            response_type: 'id_token',
            scope: 'openid profile',
            nonce: ro.nonce,
            exp: started.exp,
            display_code: started.displayCode,
            client_metadata: { client_name: 'Test RP' }
        })
        expect(ro).not.toHaveProperty('response_mode')
        expect(ro).not.toHaveProperty('state')
        expect(auth.getRequestObject(started.challenge)).toEqual(ro) // 決定的
        expect(auth.getRequestObject(auth.start().challenge).nonce).not.toBe(ro.nonce)
    })

    it('rejects unknown / expired / tampered challenges with 404', () => {
        const { challenge } = auth.start()
        clock += 300
        expect(() => auth.getRequestObject(challenge)).toThrow(expect.objectContaining({ code: 'invalid_request', status: 404 }))
        clock -= 300
        const tampered = challenge.slice(0, 20) + (challenge[20] === 'A' ? 'B' : 'A') + challenge.slice(21)
        expect(() => auth.getRequestObject(tampered)).toThrow(AuthError)
        expect(() => auth.getRequestObject('')).toThrow(AuthError)
    })

    it('honours custom paths and no client_metadata', () => {
        const a = new ConcrntAuth({ origin, secret, store, now, requestPath: '/login/concrnt/req', redirectPath: '/login/concrnt/cb' })
        const s = a.start()
        expect(s.requestUri).toBe(`${origin}/login/concrnt/req/${s.challenge}`)
        const ro = a.getRequestObject(s.challenge)
        expect(ro.redirect_uri).toBe(`${origin}/login/concrnt/cb/${s.challenge}`)
        expect(ro).not.toHaveProperty('client_metadata')
    })
})

describe('receiveDirectPost / exchange / pollResult', () => {
    // Authenticator は redirect_uri (末尾が C) に応答する。RP 側は URL から C を取ってライブラリに渡す
    const begin = () => {
        const started = auth.start()
        const ro = auth.getRequestObject(started.challenge)
        const C = ro.redirect_uri.slice(ro.redirect_uri.lastIndexOf('/') + 1)
        const respond = (overrides = {}) => ({ id_token: issueIdToken(identity, ro, origin, clock, overrides) })
        return { started, ro, C, respond }
    }

    it('direct_post goes to the mailbox and is collected exactly once by the session holder', async () => {
        const { started, C, respond } = begin()
        expect(await auth.pollResult(started.session)).toBeNull()
        await expect(auth.receiveDirectPost(C, respond())).resolves.toBeUndefined()
        const result = await auth.pollResult(started.session)
        expect(result).toMatchObject({ status: 'ok', claims: { sub: identity.ccid, name: 'Test User' } })
        expect(await auth.pollResult(started.session)).toBeNull()
        expect(await auth.pollResult('someone-else')).toBeNull()
    })

    it('exchange returns the result to the caller and never touches the mailbox', async () => {
        const { started, C, respond } = begin()
        const result = await auth.exchange(C, respond())
        expect(result).toMatchObject({ status: 'ok', claims: { sub: identity.ccid } })
        expect(await auth.pollResult(started.session)).toBeNull()
        expect(storeKeys().some((k) => k.startsWith('concrnt-auth:mailbox:'))).toBe(false)
    })

    it('a challenge is single-use across both delivery paths (§9 step 3)', async () => {
        {
            const { C, respond } = begin()
            const params = respond()
            await auth.exchange(C, params)
            await expect(auth.exchange(C, params)).rejects.toMatchObject({ code: 'request_used', status: 400 })
            await expect(auth.receiveDirectPost(C, params)).rejects.toMatchObject({ code: 'request_used' })
            // 同じチャレンジに別の ID Token を作っても使えない
            await expect(auth.exchange(C, respond())).rejects.toMatchObject({ code: 'request_used' })
        }
        {
            const { started, C, respond } = begin()
            await auth.receiveDirectPost(C, respond())
            await expect(auth.exchange(C, respond())).rejects.toMatchObject({ code: 'request_used' })
            await expect(auth.receiveDirectPost(C, respond())).rejects.toMatchObject({ code: 'request_used' })
            expect(await auth.pollResult(started.session)).toMatchObject({ status: 'ok' })
        }
    })

    it('access_denied is delivered as denied on both paths and also consumes the challenge', async () => {
        const { started, C, respond } = begin()
        await auth.receiveDirectPost(C, { error: 'access_denied' })
        expect(await auth.pollResult(started.session)).toEqual({ status: 'denied' })
        await expect(auth.exchange(C, respond())).rejects.toMatchObject({ code: 'request_used' })

        const second = begin()
        expect(await auth.exchange(second.C, { error: 'access_denied' })).toEqual({ status: 'denied' })
    })

    it('rejects missing id_token, unknown challenge and invalid ID Tokens without consuming the challenge', async () => {
        const { C, respond } = begin()
        await expect(auth.exchange('bogus', respond())).rejects.toMatchObject({ code: 'invalid_request', status: 404 })
        await expect(auth.exchange('', respond())).rejects.toMatchObject({ code: 'invalid_request', status: 404 })
        await expect(auth.exchange(C, {})).rejects.toMatchObject({ code: 'missing_id_token', status: 400 })
        await expect(auth.exchange(C, { id_token: '' })).rejects.toMatchObject({ code: 'missing_id_token', status: 400 })
        await expect(auth.exchange(C, respond({ claims: { aud: 'https://evil.example' } }))).rejects.toMatchObject({
            code: 'invalid_id_token',
            message: expect.stringContaining('aud mismatch')
        })
        await expect(auth.receiveDirectPost(C, respond({ claims: { nonce: 'x' } }))).rejects.toMatchObject({ code: 'invalid_id_token' })
        await expect(auth.exchange(C, respond({ header: { kid: 'cckv://x/keys/y' } }))).rejects.toMatchObject({ code: 'invalid_id_token' })
        await expect(auth.exchange(C, respond({ claims: { sub: 'concrnt' } }))).rejects.toMatchObject({ code: 'invalid_id_token' })
        // 失敗した応答は使用済みにしない: 正しい応答はまだ通る
        expect(await auth.exchange(C, respond())).toMatchObject({ status: 'ok' })
    })

    it('an ID Token for one challenge is not accepted at another redirect_uri (nonce binds the token to the request)', async () => {
        const a = begin()
        const b = begin()
        const idToken = issueIdToken(identity, b.ro, origin, clock)
        await expect(auth.exchange(a.C, { id_token: idToken })).rejects.toMatchObject({ code: 'invalid_id_token' })
        await expect(auth.receiveDirectPost(a.C, { id_token: idToken })).rejects.toMatchObject({ code: 'invalid_id_token' })
    })

    it('ignores tampered or foreign mailbox contents', async () => {
        const { started, C, respond } = begin()
        await auth.receiveDirectPost(C, respond())
        const key = storeKeys().find((k) => k.startsWith('concrnt-auth:mailbox:'))!
        const original = (await store.get(key))!
        // 署名を壊した封筒
        await store.set(key, original.replace(/\.[^.]+$/, '.AAAA'), 300)
        expect(await auth.pollResult(started.session)).toBeNull()
        // 別の箱の封筒を移す (sh 不一致)
        const other = begin()
        await auth.receiveDirectPost(other.C, other.respond())
        const otherKey = storeKeys().find((k) => k.startsWith('concrnt-auth:mailbox:'))!
        await store.set(key, (await store.get(otherKey))!, 300)
        expect(await auth.pollResult(started.session)).toBeNull()
        // 壊れた値
        await store.set(key, 'garbage', 300)
        expect(await auth.pollResult(started.session)).toBeNull()
    })

    it('expired challenges cannot be answered', async () => {
        const { C, respond } = begin()
        const params = respond()
        clock += 301
        await expect(auth.exchange(C, params)).rejects.toMatchObject({ code: 'invalid_request', status: 404 })
        await expect(auth.receiveDirectPost(C, params)).rejects.toMatchObject({ code: 'invalid_request', status: 404 })
    })

    it('used-marks expire with the challenge', async () => {
        const { C, respond } = begin()
        await auth.exchange(C, respond())
        expect(storeKeys().some((k) => k.startsWith('concrnt-auth:used:'))).toBe(true)
        clock += 301
        expect(await store.get(storeKeys()[0]!)).toBeNull()
    })
})

describe('parseAuthorizationResponse', () => {
    it('reads form data and fragment params alike', () => {
        const form = new FormData()
        form.set('id_token', 't')
        form.set('state', 'ignored') // 旧 Authenticator が付けてくる state は無視する
        expect(parseAuthorizationResponse(form)).toEqual({ id_token: 't', error: null })
        expect(parseAuthorizationResponse(new URLSearchParams('error=access_denied'))).toEqual({ id_token: null, error: 'access_denied' })
    })
})
