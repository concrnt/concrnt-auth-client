import { beforeEach, describe, expect, it } from 'vitest'
import { ConcrntAuth, audienceOf, authorizationRequestUri, parseAuthorizationResponse } from '../src/core.js'
import { emojihash } from '../src/emojihash.js'
import { AuthError } from '../src/errors.js'
import { MemoryStore } from '../src/store.js'
import type { AuthorizationResponseParams, StartedLogin } from '../src/types.js'
import { issueIdToken, makeIdentity, parseRequestUri } from './authenticator.js'

const origin = 'https://login-sample.test'
const callback = `${origin}/auth/callback`
let clock = 1_800_000_000
const now = () => clock
const identity = makeIdentity()

let store: MemoryStore
let auth: ConcrntAuth

beforeEach(() => {
    clock = 1_800_000_000
    store = new MemoryStore(now)
    auth = new ConcrntAuth({ origin, store, now })
})

const requestKeys = () => store.keys().filter((k) => k.startsWith('concrnt-auth:request:'))
const resultKeys = () => store.keys().filter((k) => k.startsWith('concrnt-auth:result:'))
const nonceOf = (started: StartedLogin) => parseRequestUri(started.postUri).nonce

/** Authenticator 役: URI を読んで ID Token を作る (RP への取得は無い) */
const answer = (started: StartedLogin, claims: Record<string, unknown> = {}): AuthorizationResponseParams => {
    const request = parseRequestUri(started.postUri)
    return { id_token: issueIdToken(identity, request, now(), { claims }) }
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
        expect(() => new ConcrntAuth({ origin, store, redirectPath: 'cb' })).toThrow('redirectPath')
        expect(() => new ConcrntAuth({ origin, store, redirectPath: '/cb/' })).toThrow('redirectPath')
        expect(() => new ConcrntAuth({ origin, store, redirectPath: '/cb?x=1' })).toThrow('redirectPath')
        const custom = new ConcrntAuth({ origin: 'https://rp.example:8443', store })
        expect(custom.redirectUri).toBe('https://rp.example:8443/auth/callback')
        expect(custom.audience).toBe('https://rp.example:8443/auth/callback')
    })

    it('allows http://localhost for development but keeps the identifier (aud) in https form', async () => {
        const local = new ConcrntAuth({ origin: 'http://localhost:5173', store, now })
        expect(local.redirectUri).toBe('http://localhost:5173/auth/callback')
        expect(local.audience).toBe('https://localhost:5173/auth/callback')
        const started = await local.start()
        expect(started.postUri).toMatch(/^concrnt-auth:\/\/post\/localhost:5173\/auth\/callback\?n=[A-Za-z0-9_-]{22}$/)
        const request = parseRequestUri(started.postUri)
        // Authenticator は仕様どおり aud = "https://" + host/path を入れる
        await rejects(local.exchange({ id_token: issueIdToken(identity, { ...request, audience: 'http://localhost:5173/auth/callback' }, now()) }), 'invalid_id_token', 400)
        expect((await local.exchange({ id_token: issueIdToken(identity, request, now()) })).status).toBe('ok')
    })
})

describe('start', () => {
    it('stores one request row keyed by the nonce and returns both URIs, the display code and a secret pollToken', async () => {
        const started = await auth.start()
        expect(started.postUri).toMatch(/^concrnt-auth:\/\/post\/login-sample\.test\/auth\/callback\?n=[A-Za-z0-9_-]{22}$/)
        expect(started.fragmentUri).toBe(started.postUri.replace('concrnt-auth://post/', 'concrnt-auth://fragment/'))
        const nonce = nonceOf(started)
        expect(started.displayCode).toBe(emojihash(nonce))
        expect(started.exp).toBe(now() + 300)
        expect(started.pollToken).toMatch(/^[A-Za-z0-9_-]{43}$/)
        expect('challenge' in started).toBe(false)
        expect('requestUri' in started).toBe(false)
        // pollToken は QR (URI) にもストアにも現れない
        expect(started.postUri).not.toContain(started.pollToken)
        expect(requestKeys()).toEqual([`concrnt-auth:request:${nonce}`])
        expect(JSON.stringify([...store.keys().map((k) => store.get(k))])).not.toContain(started.pollToken)
        expect(resultKeys()).toEqual([])
        // 要求ごとに nonce は変わる
        expect(nonceOf(await auth.start())).not.toBe(nonce)
    })

    it('puts the scope in the URI only when given: omitted = profile, empty = CCID only', async () => {
        expect(parseRequestUri((await auth.start()).postUri).scope).toBeNull()
        const ccidOnly = new ConcrntAuth({ origin, store, now, scope: '' })
        expect((await ccidOnly.start()).postUri).toMatch(/\?n=[A-Za-z0-9_-]{22}&s=$/)
        const custom = new ConcrntAuth({ origin, store, now, scope: 'profile foo' })
        const started = await custom.start()
        expect(started.postUri).toMatch(/&s=profile%20foo$/)
        expect(parseRequestUri(started.postUri).scope).toBe('profile foo')
    })

    it('honours custom redirectPath and ttl', async () => {
        const custom = new ConcrntAuth({ origin, store, now, redirectPath: '/x/cb', requestTtl: 60 })
        const started = await custom.start()
        expect(started.postUri).toMatch(/^concrnt-auth:\/\/post\/login-sample\.test\/x\/cb\?n=/)
        expect(started.exp).toBe(now() + 60)
        expect(custom.audience).toBe(`${origin}/x/cb`)
    })
})

describe('authorizationRequestUri / audienceOf', () => {
    const nonce = 'atuQzACZAhdDWdWSKoLkIg'

    it('builds the URI from the redirect URL and nonce', () => {
        expect(authorizationRequestUri('https://example.com/api/auth/concrnt/callback', 'post', nonce)).toBe(
            `concrnt-auth://post/example.com/api/auth/concrnt/callback?n=${nonce}`
        )
        expect(authorizationRequestUri('https://example.com:8443/cb', 'fragment', nonce, '')).toBe(`concrnt-auth://fragment/example.com:8443/cb?n=${nonce}&s=`)
        expect(authorizationRequestUri('http://localhost/cb', 'post', nonce, 'profile x')).toBe(`concrnt-auth://post/localhost/cb?n=${nonce}&s=profile%20x`)
        expect(audienceOf('http://127.0.0.1:3000/cb')).toBe('https://127.0.0.1:3000/cb')
        expect(audienceOf('https://example.com/cb')).toBe('https://example.com/cb')
    })

    it('rejects unknown modes, bad nonces and redirect URLs the URI syntax cannot express', () => {
        expect(() => authorizationRequestUri('https://x.test/a', 'direct_post' as never, nonce)).toThrow('unknown response type')
        expect(() => authorizationRequestUri('https://x.test/a', 'post', 'short')).toThrow('nonce')
        expect(() => authorizationRequestUri('http://x.test/a', 'post', nonce)).toThrow('must be https')
        expect(() => authorizationRequestUri('https://user@x.test/a', 'post', nonce)).toThrow('userinfo')
        expect(() => authorizationRequestUri('https://x.test', 'post', nonce)).toThrow('path must not be empty')
        expect(() => authorizationRequestUri('https://x.test/', 'post', nonce)).toThrow('path must not be empty')
        expect(() => authorizationRequestUri('https://x.test/a?b=1', 'post', nonce)).toThrow('query or fragment')
        expect(() => authorizationRequestUri('https://x.test/a#f', 'post', nonce)).toThrow('query or fragment')
        expect(() => authorizationRequestUri('nope', 'post', nonce)).toThrow('not a URL')
    })
})

describe('receivePost / exchange / pollResult', () => {
    it('post stashes the result for the pollToken holder, who collects it exactly once', async () => {
        const started = await auth.start()
        expect(await auth.pollResult(started.pollToken)).toBeNull()
        const params = answer(started)
        await auth.receivePost(params)
        expect(requestKeys()).toEqual([]) // 要求の行は消費された
        expect(resultKeys()).toHaveLength(1)
        expect(await auth.pollResult('wrong-token')).toBeNull()
        const result = await auth.pollResult(started.pollToken)
        expect(result?.status).toBe('ok')
        if (result?.status !== 'ok') throw new Error('unreachable')
        expect(result.claims.sub).toBe(identity.ccid)
        expect(result.claims.aud).toBe(callback)
        expect(result.claims.name).toBe('Test User')
        expect(result.idToken).toBe(params.id_token)
        expect(result.context).toBeUndefined()
        expect(await auth.pollResult(started.pollToken)).toBeNull() // 読んだら消える
    })

    it('exchange returns the result to the presenter and never feeds the starting browser (§8.2)', async () => {
        const started = await auth.start()
        const result = await auth.exchange(answer(started))
        expect(result.status).toBe('ok')
        expect(resultKeys()).toEqual([])
        expect(await auth.pollResult(started.pollToken)).toBeNull()
    })

    it('a request is single-use across both delivery paths (§9 step 7)', async () => {
        const a = await auth.start()
        const pa = answer(a)
        await auth.receivePost(pa)
        await rejects(auth.receivePost(pa), 'invalid_request', 404)
        await rejects(auth.exchange(pa), 'invalid_request', 404)

        const b = await auth.start()
        const pb = answer(b)
        await auth.exchange(pb)
        await rejects(auth.exchange(pb), 'invalid_request', 404)
        await rejects(auth.receivePost(pb), 'invalid_request', 404)
    })

    it('accepts exactly one of two concurrent valid responses (atomic consume)', async () => {
        const started = await auth.start()
        const params = answer(started)
        const outcomes = await Promise.allSettled([auth.exchange(params), auth.exchange(params)])
        const ok = outcomes.filter((o) => o.status === 'fulfilled')
        const failed = outcomes.filter((o) => o.status === 'rejected') as PromiseRejectedResult[]
        expect(ok).toHaveLength(1)
        expect(failed).toHaveLength(1)
        expect((failed[0]!.reason as AuthError).code).toBe('request_used')
    })

    it('access_denied with the nonce is delivered as denied on both paths and consumes the request (§8.3)', async () => {
        const a = await auth.start()
        await auth.receivePost({ error: 'access_denied', nonce: nonceOf(a) })
        expect(await auth.pollResult(a.pollToken)).toEqual({ status: 'denied', context: undefined })
        await rejects(auth.exchange(answer(a)), 'invalid_request', 404)

        const b = await auth.start()
        expect(await auth.exchange({ id_token: null, error: 'access_denied', nonce: nonceOf(b) })).toEqual({ status: 'denied', context: undefined })
    })

    it('rejects a denial without a nonce or with an unknown nonce, leaving the request intact', async () => {
        const started = await auth.start()
        await rejects(auth.receivePost({ error: 'access_denied' }), 'missing_nonce', 400)
        await rejects(auth.receivePost({ error: 'access_denied', nonce: '' }), 'missing_nonce', 400)
        await rejects(auth.receivePost({ error: 'access_denied', nonce: 'AAAAAAAAAAAAAAAAAAAAAA' }), 'invalid_request', 404)
        expect(requestKeys()).toHaveLength(1)
        expect((await auth.exchange(answer(started))).status).toBe('ok')
    })

    it('rejects missing id_token, unknown nonces and invalid ID Tokens without consuming the request', async () => {
        const started = await auth.start()
        const request = parseRequestUri(started.postUri)
        await rejects(auth.exchange({}), 'missing_id_token', 400)
        await rejects(auth.exchange({ id_token: '', error: 'server_error' }), 'missing_id_token', 400)
        await rejects(auth.exchange({ id_token: 'not.a.jwt' }), 'invalid_id_token', 400)
        await rejects(auth.exchange({ id_token: 'x' }), 'invalid_id_token', 400)
        // 正しく署名されているが、こちらが発行していない nonce → 行が無い (偽造 URI のトークンはここで捨てられる)
        await rejects(auth.exchange({ id_token: issueIdToken(identity, { ...request, nonce: 'AAAAAAAAAAAAAAAAAAAAAA' }, now()) }), 'invalid_request', 404)
        // aud 違い: オリジンだけ・末尾スラッシュ・オープンリダイレクタ経由・他ホストの同じパス
        for (const aud of [origin, `${callback}/`, `${origin}/redirect?to=${encodeURIComponent(callback)}`, 'https://evil.test/auth/callback']) {
            await rejects(auth.exchange({ id_token: issueIdToken(identity, { ...request, audience: aud }, now()) }), 'invalid_id_token', 400)
        }
        // exp は iat + 300 固定
        for (const delta of [299, 301, 3600]) {
            await rejects(auth.exchange({ id_token: issueIdToken(identity, request, now(), { claims: { exp: now() + delta } }) }), 'invalid_id_token', 400)
        }
        // 署名改ざん
        await rejects(auth.exchange({ id_token: issueIdToken(identity, request, now(), { mutateSignature: (s) => (s[0] ^= 1) }) }), 'invalid_id_token', 400)
        // まだ使える
        expect(requestKeys()).toHaveLength(1)
        expect((await auth.exchange(answer(started))).status).toBe('ok')
    })

    it('expired requests cannot be answered, and a stashed result survives the request expiry for a grace period', async () => {
        const a = await auth.start()
        const params = answer(a)
        clock += 301
        await rejects(auth.receivePost(params), 'invalid_request', 404)

        clock = 1_800_000_000
        const b = await auth.start()
        await auth.receivePost(answer(b))
        clock += 330 // 要求は失効したが結果は 60 秒の猶予内
        expect((await auth.pollResult(b.pollToken))?.status).toBe('ok')

        const c = await auth.start()
        await auth.receivePost(answer(c))
        clock += 400
        expect(await auth.pollResult(c.pollToken)).toBeNull()
    })

    it('round-trips a per-request context on both paths', async () => {
        type Ctx = { callbackURL: string; userId?: string }
        const typed = new ConcrntAuth<Ctx>({ origin, store, now })
        const a = await typed.start({ callbackURL: '/after', userId: 'u1' })
        await typed.receivePost(answer(a))
        const polled = await typed.pollResult(a.pollToken)
        expect(polled?.context).toEqual({ callbackURL: '/after', userId: 'u1' })

        const b = await typed.start({ callbackURL: '/x' })
        const exchanged = await typed.exchange(answer(b))
        expect(exchanged.context).toEqual({ callbackURL: '/x' })

        const c = await typed.start({ callbackURL: '/y' })
        expect(await typed.exchange({ error: 'access_denied', nonce: nonceOf(c) })).toEqual({ status: 'denied', context: { callbackURL: '/y' } })
    })
})

describe('parseAuthorizationResponse', () => {
    it('reads form data, fragment params and JSON bodies alike, ignoring unknown and non-string values', () => {
        const form = new FormData()
        form.set('id_token', 'a.b.c')
        form.set('state', 'ignored')
        expect(parseAuthorizationResponse(form)).toEqual({ id_token: 'a.b.c', error: null, nonce: null })
        expect(parseAuthorizationResponse(new URLSearchParams('error=access_denied&nonce=N&x=1'))).toEqual({ id_token: null, error: 'access_denied', nonce: 'N' })
        expect(parseAuthorizationResponse({ id_token: 'a.b.c', error: 5, nonce: 1, other: true })).toEqual({ id_token: 'a.b.c', error: null, nonce: null })
        expect(parseAuthorizationResponse({})).toEqual({ id_token: null, error: null, nonce: null })
    })
})
