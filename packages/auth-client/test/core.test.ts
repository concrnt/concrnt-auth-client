import { beforeEach, describe, expect, it } from 'vitest'
import { ConcrntAuth, authorizationRequestUri, parseAuthorizationResponse } from '../src/core.js'
import { AuthError } from '../src/errors.js'
import { MemoryStore } from '../src/store.js'
import type { AuthorizationResponseParams, RequestObject, StartedLogin } from '../src/types.js'
import { issueIdToken, makeIdentity } from './authenticator.js'

const origin = 'https://login-sample.test'
let clock = 1_800_000_000
const now = () => clock
const identity = makeIdentity()

let store: MemoryStore
let auth: ConcrntAuth

beforeEach(() => {
    clock = 1_800_000_000
    store = new MemoryStore(now)
    auth = new ConcrntAuth({ origin, store, now, clientMetadata: { client_name: 'Test RP' } })
})

const requestKeys = () => store.keys().filter((k) => k.startsWith('concrnt-auth:request:'))
const resultKeys = () => store.keys().filter((k) => k.startsWith('concrnt-auth:result:'))

/** Authenticator 役: Request Object を取って ID Token を作る */
const answer = async (started: StartedLogin, claims: Record<string, unknown> = {}): Promise<{ ro: RequestObject; params: AuthorizationResponseParams }> => {
    const ro = await auth.getRequestObject(started.challenge)
    return { ro, params: { id_token: issueIdToken(identity, ro, origin, now(), { claims }) } }
}

const rejects = async (p: Promise<unknown>, code: string, status?: number) => {
    const e = await p.then(
        () => null,
        (e) => e
    )
    expect(e).toBeInstanceOf(AuthError)
    expect((e as AuthError).code).toBe(code)
    if (status) expect((e as AuthError).status).toBe(status)
}

describe('constructor', () => {
    it('rejects non-https origins except localhost, paths and trailing slashes', () => {
        expect(() => new ConcrntAuth({ origin: 'http://example.com', store })).toThrow(AuthError)
        expect(() => new ConcrntAuth({ origin: 'https://example.com/', store })).toThrow('without path')
        expect(() => new ConcrntAuth({ origin: 'https://example.com/app', store })).toThrow('without path')
        expect(() => new ConcrntAuth({ origin: 'not a url', store })).toThrow('not a URL')
        expect(() => new ConcrntAuth({ origin, store, requestPath: 'auth' })).toThrow('requestPath')
        expect(() => new ConcrntAuth({ origin, store, redirectPath: '/cb/' })).toThrow('redirectPath')
        expect(new ConcrntAuth({ origin: 'http://localhost:5173', store }).origin).toBe('http://localhost:5173')
        expect(new ConcrntAuth({ origin: 'https://rp.example:8443', store }).redirectUriFor('C')).toBe('https://rp.example:8443/auth/callback/C')
    })
})

describe('start / getRequestObject', () => {
    it('stores one request row and returns both Authorization Request URIs, the display code and a secret pollToken', async () => {
        const started = await auth.start()
        expect(started.challenge).toMatch(/^[A-Za-z0-9_-]{22}$/)
        expect(started.requestUri).toBe(`${origin}/auth/request/${started.challenge}`)
        expect(started.directPostUri).toBe(`concrnt-auth://direct_post/login-sample.test/auth/request/${started.challenge}`)
        expect(started.fragmentUri).toBe(`concrnt-auth://fragment/login-sample.test/auth/request/${started.challenge}`)
        expect(started.exp).toBe(now() + 300)
        expect(started.pollToken).toMatch(/^[A-Za-z0-9_-]{43}$/)
        expect(started.displayCode.length).toBeGreaterThan(0)
        // pollToken は QR (URI) にもストアにも現れない
        expect(started.directPostUri).not.toContain(started.pollToken)
        expect(requestKeys()).toEqual([`concrnt-auth:request:${started.challenge}`])
        expect(JSON.stringify([...store.keys().map((k) => store.get(k))])).not.toContain(started.pollToken)
        expect(resultKeys()).toEqual([])
    })

    it('authorizationRequestUri rejects unknown modes and non-https request_uri', () => {
        expect(() => authorizationRequestUri('https://x.test/a', 'query' as never)).toThrow('unknown response_mode')
        expect(() => authorizationRequestUri('http://x.test/a', 'fragment')).toThrow('must be https')
    })

    it('serves the same Request Object for both modes with display_code and a per-request redirect_uri', async () => {
        const started = await auth.start()
        const ro = await auth.getRequestObject(started.challenge)
        expect(ro).toEqual({
            redirect_uri: `${origin}/auth/callback/${started.challenge}`,
            response_type: 'id_token',
            scope: 'openid profile',
            nonce: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
            exp: started.exp,
            display_code: started.displayCode,
            client_metadata: { client_name: 'Test RP' }
        })
        expect(await auth.getRequestObject(started.challenge)).toEqual(ro) // 再取得できる (§5.2 の一回限りは SHOULD)
        const other = await auth.start()
        expect((await auth.getRequestObject(other.challenge)).nonce).not.toBe(ro.nonce)
    })

    it('rejects unknown and expired challenges with 404', async () => {
        await rejects(auth.getRequestObject('nope'), 'invalid_request', 404)
        const started = await auth.start()
        clock += 301
        await rejects(auth.getRequestObject(started.challenge), 'invalid_request', 404)
    })

    it('honours custom paths, ttl and no client_metadata', async () => {
        const custom = new ConcrntAuth({ origin, store, now, requestPath: '/x/req', redirectPath: '/x/cb', requestTtl: 60 })
        const started = await custom.start()
        expect(started.requestUri).toBe(`${origin}/x/req/${started.challenge}`)
        expect(started.exp).toBe(now() + 60)
        const ro = await custom.getRequestObject(started.challenge)
        expect(ro.redirect_uri).toBe(`${origin}/x/cb/${started.challenge}`)
        expect('client_metadata' in ro).toBe(false)
    })
})

describe('receiveDirectPost / exchange / pollResult', () => {
    it('direct_post stashes the result for the pollToken holder, who collects it exactly once', async () => {
        const started = await auth.start()
        expect(await auth.pollResult(started.pollToken)).toBeNull()
        const { params } = await answer(started)
        await auth.receiveDirectPost(started.challenge, params)
        expect(requestKeys()).toEqual([]) // 要求の行は消費された
        expect(resultKeys()).toHaveLength(1)
        expect(await auth.pollResult('wrong-token')).toBeNull()
        const result = await auth.pollResult(started.pollToken)
        expect(result?.status).toBe('ok')
        if (result?.status !== 'ok') throw new Error('unreachable')
        expect(result.claims.sub).toBe(identity.ccid)
        expect(result.claims.name).toBe('Test User')
        expect(result.idToken).toBe(params.id_token)
        expect(result.context).toBeUndefined()
        expect(await auth.pollResult(started.pollToken)).toBeNull() // 読んだら消える
    })

    it('exchange returns the result to the presenter and never feeds the starting browser (§8.2)', async () => {
        const started = await auth.start()
        const { params } = await answer(started)
        const result = await auth.exchange(started.challenge, params)
        expect(result.status).toBe('ok')
        expect(resultKeys()).toEqual([])
        expect(await auth.pollResult(started.pollToken)).toBeNull()
    })

    it('a request is single-use across both delivery paths (§9 step 3)', async () => {
        const a = await auth.start()
        const { params: pa } = await answer(a)
        await auth.receiveDirectPost(a.challenge, pa)
        await rejects(auth.receiveDirectPost(a.challenge, pa), 'invalid_request', 404)
        await rejects(auth.exchange(a.challenge, pa), 'invalid_request', 404)
        await rejects(auth.getRequestObject(a.challenge), 'invalid_request', 404)

        const b = await auth.start()
        const { params: pb } = await answer(b)
        await auth.exchange(b.challenge, pb)
        await rejects(auth.exchange(b.challenge, pb), 'invalid_request', 404)
        await rejects(auth.receiveDirectPost(b.challenge, pb), 'invalid_request', 404)
    })

    it('accepts exactly one of two concurrent valid responses (atomic consume)', async () => {
        const started = await auth.start()
        const { params } = await answer(started)
        const outcomes = await Promise.allSettled([auth.exchange(started.challenge, params), auth.exchange(started.challenge, params)])
        const ok = outcomes.filter((o) => o.status === 'fulfilled')
        const failed = outcomes.filter((o) => o.status === 'rejected') as PromiseRejectedResult[]
        expect(ok).toHaveLength(1)
        expect(failed).toHaveLength(1)
        expect((failed[0]!.reason as AuthError).code).toBe('request_used')
    })

    it('access_denied is delivered as denied on both paths and consumes the request', async () => {
        const a = await auth.start()
        await auth.receiveDirectPost(a.challenge, { error: 'access_denied' })
        expect(await auth.pollResult(a.pollToken)).toEqual({ status: 'denied', context: undefined })
        await rejects(auth.getRequestObject(a.challenge), 'invalid_request')

        const b = await auth.start()
        expect(await auth.exchange(b.challenge, { id_token: null, error: 'access_denied' })).toEqual({ status: 'denied', context: undefined })
    })

    it('rejects missing id_token, unknown challenges and invalid ID Tokens without consuming the request', async () => {
        const started = await auth.start()
        const { ro } = await answer(started)
        await rejects(auth.exchange(started.challenge, {}), 'missing_id_token', 400)
        await rejects(auth.exchange(started.challenge, { id_token: '', error: 'server_error' }), 'missing_id_token', 400)
        await rejects(auth.exchange('unknown', { id_token: 'x' }), 'invalid_request', 404)
        await rejects(auth.exchange(started.challenge, { id_token: 'not.a.jwt' }), 'invalid_id_token', 400)
        // nonce 違い
        await rejects(auth.exchange(started.challenge, { id_token: issueIdToken(identity, { ...ro, nonce: 'other' }, origin, now()) }), 'invalid_id_token', 400)
        // aud 違い
        await rejects(auth.exchange(started.challenge, { id_token: issueIdToken(identity, ro, 'https://evil.test', now()) }), 'invalid_id_token', 400)
        // 署名改ざん
        await rejects(
            auth.exchange(started.challenge, { id_token: issueIdToken(identity, ro, origin, now(), { mutateSignature: (s) => (s[0] ^= 1) }) }),
            'invalid_id_token',
            400
        )
        // まだ使える
        expect((await auth.exchange(started.challenge, { id_token: issueIdToken(identity, ro, origin, now()) })).status).toBe('ok')
    })

    it('an ID Token issued for one request is not accepted at another redirect_uri (nonce binds the token to the request)', async () => {
        const a = await auth.start()
        const b = await auth.start()
        const { params } = await answer(a)
        await rejects(auth.exchange(b.challenge, params), 'invalid_id_token', 400)
        expect((await auth.exchange(a.challenge, params)).status).toBe('ok')
    })

    it('expired requests cannot be answered, and a stashed result survives the request expiry for a grace period', async () => {
        const a = await auth.start()
        const { params } = await answer(a)
        clock += 301
        await rejects(auth.receiveDirectPost(a.challenge, params), 'invalid_request', 404)

        clock = 1_800_000_000
        const b = await auth.start()
        const { params: pb } = await answer(b)
        await auth.receiveDirectPost(b.challenge, pb)
        clock += 330 // 要求は失効したが結果は 60 秒の猶予内
        expect((await auth.pollResult(b.pollToken))?.status).toBe('ok')

        const c = await auth.start()
        const { params: pc } = await answer(c)
        await auth.receiveDirectPost(c.challenge, pc)
        clock += 400
        expect(await auth.pollResult(c.pollToken)).toBeNull()
    })

    it('round-trips a per-request context on both paths', async () => {
        type Ctx = { callbackURL: string; userId?: string }
        const typed = new ConcrntAuth<Ctx>({ origin, store, now })
        const a = await typed.start({ callbackURL: '/after', userId: 'u1' })
        const { params } = await answer(a)
        await typed.receiveDirectPost(a.challenge, params)
        const polled = await typed.pollResult(a.pollToken)
        expect(polled?.context).toEqual({ callbackURL: '/after', userId: 'u1' })

        const b = await typed.start({ callbackURL: '/x' })
        const { params: pb } = await answer(b)
        const exchanged = await typed.exchange(b.challenge, pb)
        expect(exchanged.context).toEqual({ callbackURL: '/x' })

        const c = await typed.start({ callbackURL: '/y' })
        expect(await typed.exchange(c.challenge, { error: 'access_denied' })).toEqual({ status: 'denied', context: { callbackURL: '/y' } })
    })
})

describe('parseAuthorizationResponse', () => {
    it('reads form data, fragment params and JSON bodies alike, ignoring unknown and non-string values', () => {
        const form = new FormData()
        form.set('id_token', 'a.b.c')
        form.set('state', 'ignored')
        expect(parseAuthorizationResponse(form)).toEqual({ id_token: 'a.b.c', error: null })
        expect(parseAuthorizationResponse(new URLSearchParams('error=access_denied&x=1'))).toEqual({ id_token: null, error: 'access_denied' })
        expect(parseAuthorizationResponse({ id_token: 'a.b.c', error: 5, other: true })).toEqual({ id_token: 'a.b.c', error: null })
        expect(parseAuthorizationResponse({})).toEqual({ id_token: null, error: null })
    })
})
