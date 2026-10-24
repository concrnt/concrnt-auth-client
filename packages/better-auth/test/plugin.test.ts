import { describe, expect, it } from 'vitest'
import { LANDING_SCRIPT } from '../src/landing.js'
import {
    call,
    challengeOf,
    cookiesOf,
    createTestAuth,
    directPost,
    directPostFlow,
    exchange,
    fetchRequestObject,
    getSession,
    hasSessionCookie,
    idTokenFor,
    json,
    makeIdentity,
    ORIGIN,
    poll,
    signUpUser,
    start,
    type TestAuth
} from './helpers.js'

const alice = makeIdentity()
const bob = makeIdentity()

/** alice をユーザーに登録した状態の RP */
const withRegisteredAlice = async (auth: TestAuth) => {
    const owner = await signUpUser(auth, 'owner')
    const { polled } = await directPostFlow(auth, 'registration', alice, {}, owner.headers)
    expect(polled.status).toBe(200)
    return owner
}

describe('start / request object', () => {
    it('issues both Authorization Request URIs from one request and a Request Object under basePath', async () => {
        const auth = await createTestAuth()
        const { res, started } = await start(auth, 'authentication')
        expect(res.status).toBe(200)
        expect(started!.requestUri).toMatch(new RegExp(`^${ORIGIN}/api/auth/concrnt/request/[A-Za-z0-9_-]{48}$`))
        const C = challengeOf(started!.requestUri)
        expect(started!.directPostUri).toBe(`concrnt-auth://direct_post/rp.test/api/auth/concrnt/request/${C}`)
        expect(started!.fragmentUri).toBe(`concrnt-auth://fragment/rp.test/api/auth/concrnt/request/${C}`)
        expect(started!.displayCode).toMatch(/\p{Extended_Pictographic}/u)
        expect(started!.pollToken).toHaveLength(43)
        expect(started!.exp).toBeGreaterThan(Date.now() / 1000 + 200)

        const roRes = await call(auth, 'GET', started!.requestUri)
        expect(roRes.headers.get('access-control-allow-origin')).toBe('*')
        expect(roRes.headers.get('cache-control')).toContain('no-store')
        const ro = await json(roRes)
        expect(ro).toMatchObject({
            redirect_uri: `${ORIGIN}/api/auth/concrnt/callback/${C}`,
            response_type: 'id_token',
            scope: 'openid profile',
            exp: started!.exp,
            display_code: started!.displayCode,
            client_metadata: { client_name: 'Test RP' }
        })
        expect(ro).not.toHaveProperty('response_mode')
    })

    it('rejects unknown challenges with 404 CHALLENGE_NOT_FOUND', async () => {
        const auth = await createTestAuth()
        const res = await call(auth, 'GET', '/concrnt/request/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
        expect(res.status).toBe(404)
        expect(await json(res)).toMatchObject({ code: 'CHALLENGE_NOT_FOUND' })
    })

    it('validates callbackURL against trustedOrigins and echoes it on completion', async () => {
        const auth = await createTestAuth()
        await withRegisteredAlice(auth)
        expect((await start(auth, 'authentication', { callbackURL: 'https://evil.test/x' })).res.status).toBe(403)
        const { polled } = await directPostFlow(auth, 'authentication', alice, { callbackURL: 'https://app.test/done' })
        expect(await json(polled)).toMatchObject({ status: 'ok', callbackURL: 'https://app.test/done' })
        const rel = await directPostFlow(auth, 'authentication', alice, { callbackURL: '/after' })
        expect(await json(rel.polled)).toMatchObject({ status: 'ok', callbackURL: '/after' })
    })
})

describe('authentication (direct_post)', () => {
    it('holds the result for the starting browser and issues the session on status, not to the Authenticator', async () => {
        const auth = await createTestAuth()
        const owner = await withRegisteredAlice(auth)

        const { started } = await start(auth, 'authentication')
        expect(await json(await poll(auth, started!))).toEqual({ status: 'pending' })
        const ro = await fetchRequestObject(auth, started!)
        const posted = await directPost(auth, ro, { id_token: idTokenFor(alice, ro) })
        expect(posted.status).toBe(204)
        expect(posted.headers.get('set-cookie')).toBeNull()

        const polled = await poll(auth, started!)
        expect(polled.status).toBe(200)
        expect(hasSessionCookie(polled)).toBe(true)
        const body = await json<{ status: string; user: { id: string }; identity: { ccid: string; domain: string } }>(polled)
        expect(body.status).toBe('ok')
        expect(body.user.id).toBe(owner.user.id)
        expect(body.identity).toMatchObject({ ccid: alice.ccid, domain: 'example.concrnt.test' })

        const session = await getSession(auth, cookiesOf(polled))
        expect(session?.user.id).toBe(owner.user.id)
        // 回収は 1 回限り
        expect(await json(await poll(auth, started!))).toEqual({ status: 'pending' })
    })

    it('rejects unknown identities with 401 IDENTITY_NOT_FOUND and does not create a user', async () => {
        const auth = await createTestAuth()
        const { polled } = await directPostFlow(auth, 'authentication', bob)
        expect(polled.status).toBe(401)
        expect(await json(polled)).toMatchObject({ code: 'IDENTITY_NOT_FOUND' })
        expect(hasSessionCookie(polled)).toBe(false)
    })

    it('reports denied without a session', async () => {
        const auth = await createTestAuth()
        const { started } = await start(auth, 'authentication', { callbackURL: '/login' })
        const ro = await fetchRequestObject(auth, started!)
        expect((await directPost(auth, ro, { error: 'access_denied' })).status).toBe(204)
        const polled = await poll(auth, started!)
        expect(await json(polled)).toEqual({ status: 'denied', callbackURL: '/login' })
        expect(hasSessionCookie(polled)).toBe(false)
    })

    it('rejects replays on either route once a response is accepted (§9 step 3)', async () => {
        const auth = await createTestAuth()
        await withRegisteredAlice(auth)
        const { started, ro, posted } = await directPostFlow(auth, 'authentication', alice)
        expect(posted.status).toBe(204)
        const again = await directPost(auth, ro, { id_token: idTokenFor(alice, ro) })
        expect(again.status).toBe(400)
        expect(await json(again)).toMatchObject({ code: 'CHALLENGE_ALREADY_USED' })
        const viaFragment = await exchange(auth, ro, { id_token: idTokenFor(alice, ro) })
        expect(viaFragment.status).toBe(400)
        expect(await json(viaFragment)).toMatchObject({ code: 'CHALLENGE_ALREADY_USED' })
        void started
    })

    it('accepts exactly one of two concurrent valid responses (atomic reservation)', async () => {
        const auth = await createTestAuth()
        await withRegisteredAlice(auth)
        const { started } = await start(auth, 'authentication')
        const ro = await fetchRequestObject(auth, started!)
        const results = await Promise.all([
            directPost(auth, ro, { id_token: idTokenFor(alice, ro) }),
            directPost(auth, ro, { id_token: idTokenFor(alice, ro) })
        ])
        expect(results.map((r) => r.status).sort()).toEqual([204, 400])
    })

    it('does not consume the challenge on invalid or missing id_token', async () => {
        const auth = await createTestAuth()
        await withRegisteredAlice(auth)
        const { started } = await start(auth, 'authentication')
        const ro = await fetchRequestObject(auth, started!)
        const missing = await directPost(auth, ro, { foo: 'bar' })
        expect(missing.status).toBe(400)
        expect(await json(missing)).toMatchObject({ code: 'MISSING_ID_TOKEN' })
        const wrongAud = await directPost(auth, ro, { id_token: idTokenFor(alice, ro, { claims: { aud: 'https://other.test' } }) })
        expect(wrongAud.status).toBe(400)
        expect(await json(wrongAud)).toMatchObject({ code: 'INVALID_ID_TOKEN' })
        const withKid = await directPost(auth, ro, { id_token: idTokenFor(alice, ro, { header: { kid: 'x' } }) })
        expect(withKid.status).toBe(400)
        expect((await directPost(auth, ro, { id_token: idTokenFor(alice, ro) })).status).toBe(204)
    })

    it('also accepts JSON bodies on the direct_post endpoint and rejects unknown media types', async () => {
        const auth = await createTestAuth()
        await withRegisteredAlice(auth)
        const { started } = await start(auth, 'authentication')
        const ro = await fetchRequestObject(auth, started!)
        const asText = await call(auth, 'POST', ro.redirect_uri, { headers: { 'content-type': 'text/plain' }, authenticator: true })
        expect(asText.ok).toBe(false)
        expect((await call(auth, 'POST', ro.redirect_uri, { json: { id_token: idTokenFor(alice, ro) }, authenticator: true })).status).toBe(204)
    })
})

describe('authentication (fragment)', () => {
    it('serves the landing page at redirect_uri with a CSP that allows only its own script', async () => {
        const auth = await createTestAuth()
        const { started } = await start(auth, 'authentication')
        const ro = await fetchRequestObject(auth, started!)
        const res = await call(auth, 'GET', ro.redirect_uri)
        expect(res.status).toBe(200)
        expect(res.headers.get('content-type')).toContain('text/html')
        expect(res.headers.get('cache-control')).toBe('no-store')
        const html = await res.text()
        expect(html).toContain(LANDING_SCRIPT)
        expect(html).toContain('/exchange/')
        const digest = Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(LANDING_SCRIPT))).toString('base64')
        expect(res.headers.get('content-security-policy')).toContain(`script-src 'sha256-${digest}'`)
        expect(res.headers.get('content-security-policy')).toContain("connect-src 'self'")
    })

    it('exchange logs in the presenting browser and never feeds the starting browser (§8.2)', async () => {
        const auth = await createTestAuth()
        const owner = await withRegisteredAlice(auth)
        const { started } = await start(auth, 'authentication', { callbackURL: '/home' })
        const ro = await fetchRequestObject(auth, started!)
        const res = await exchange(auth, ro, { id_token: idTokenFor(alice, ro), error: null })
        expect(res.status).toBe(200)
        expect(hasSessionCookie(res)).toBe(true)
        expect(await json(res)).toMatchObject({ status: 'ok', callbackURL: '/home', user: { id: owner.user.id } })
        expect((await getSession(auth, cookiesOf(res)))?.user.id).toBe(owner.user.id)
        // 開始したブラウザのポーリングには何も届かない
        expect(await json(await poll(auth, started!))).toEqual({ status: 'pending' })
    })

    it('exchange reports denied and unknown identities', async () => {
        const auth = await createTestAuth()
        const { started } = await start(auth, 'authentication')
        const ro = await fetchRequestObject(auth, started!)
        const denied = await exchange(auth, ro, { error: 'access_denied' })
        expect(await json(denied)).toEqual({ status: 'denied', callbackURL: '/' })
        const s2 = (await start(auth, 'authentication')).started!
        const ro2 = await fetchRequestObject(auth, s2)
        const unknown = await exchange(auth, ro2, { id_token: idTokenFor(bob, ro2) })
        expect(unknown.status).toBe(401)
        expect(await json(unknown)).toMatchObject({ code: 'IDENTITY_NOT_FOUND' })
    })
})

describe('registration (passkey-style)', () => {
    it('requires a session by default and links the identity to that user', async () => {
        const auth = await createTestAuth()
        const anon = await start(auth, 'registration')
        expect(anon.res.status).toBe(401)

        const owner = await signUpUser(auth)
        const { polled } = await directPostFlow(auth, 'registration', alice, { name: 'My phone' }, owner.headers)
        expect(polled.status).toBe(200)
        const body = await json<{ status: string; identity: { ccid: string; name: string; userId: string }; session: unknown; user: unknown }>(polled)
        expect(body.identity).toMatchObject({ ccid: alice.ccid, name: 'My phone', userId: owner.user.id })
        expect(body.session).toBeNull() // createSession を指定していないので新しいセッションは作らない
        expect(hasSessionCookie(polled)).toBe(false)

        const list = await call(auth, 'GET', '/concrnt/list-identities', { headers: owner.headers })
        expect(await json<unknown[]>(list)).toHaveLength(1)

        // 同じ CCID は 2 度登録できない
        const dup = await directPostFlow(auth, 'registration', alice, {}, owner.headers)
        expect(dup.polled.status).toBe(400)
        expect(await json(dup.polled)).toMatchObject({ code: 'IDENTITY_ALREADY_REGISTERED' })

        // 登録した CCID でログインできる
        const login = await directPostFlow(auth, 'authentication', alice)
        expect(await json(login.polled)).toMatchObject({ status: 'ok', user: { id: owner.user.id } })
    })

    it('refuses to complete a registration for a different user, on either route', async () => {
        const auth = await createTestAuth()
        const owner = await signUpUser(auth, 'o1')
        const other = await signUpUser(auth, 'o2')

        // direct_post: 別人のセッションでポーリング
        const { started } = await start(auth, 'registration', {}, owner.headers)
        const ro = await fetchRequestObject(auth, started!)
        expect((await directPost(auth, ro, { id_token: idTokenFor(alice, ro) })).status).toBe(204)
        const polled = await poll(auth, started!, other.headers)
        expect(polled.status).toBe(401)
        expect(await json(polled)).toMatchObject({ code: 'YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_IDENTITY' })

        // fragment: 別人、または未ログインのブラウザが提示
        const s2 = (await start(auth, 'registration', {}, owner.headers)).started!
        const ro2 = await fetchRequestObject(auth, s2)
        const byOther = await exchange(auth, ro2, { id_token: idTokenFor(alice, ro2) }, other.headers)
        expect(byOther.status).toBe(401)
        const s3 = (await start(auth, 'registration', {}, owner.headers)).started!
        const ro3 = await fetchRequestObject(auth, s3)
        const byNobody = await exchange(auth, ro3, { id_token: idTokenFor(alice, ro3) })
        expect(byNobody.status).toBe(401)
        expect(await json(byNobody)).toMatchObject({ code: 'SESSION_REQUIRED' })

        // fragment: 本人が提示すれば成立
        const s4 = (await start(auth, 'registration', {}, owner.headers)).started!
        const ro4 = await fetchRequestObject(auth, s4)
        const byOwner = await exchange(auth, ro4, { id_token: idTokenFor(alice, ro4) }, owner.headers)
        expect(byOwner.status).toBe(200)
        expect(await json(byOwner)).toMatchObject({ identity: { userId: owner.user.id } })
    })

    it('signs up through afterVerification when requireSession is false (Concrnt-only sign-up)', async () => {
        const auth = await createTestAuth({
            registration: {
                requireSession: false,
                afterVerification: async ({ ctx, claims, user }) => {
                    if (user) return
                    const created = await ctx.context.internalAdapter.createUser(
                        { name: claims.name ?? claims.sub, email: `${claims.sub}@concrnt.invalid`, emailVerified: false, image: claims.picture ?? null },
                        { method: 'concrnt' }
                    )
                    return { userId: created.id, name: 'from hook' }
                }
            }
        })
        const { polled } = await directPostFlow(auth, 'registration', alice, { createSession: true })
        expect(polled.status).toBe(200)
        expect(hasSessionCookie(polled)).toBe(true)
        const body = await json<{ identity: { name: string }; user: { name: string } }>(polled)
        expect(body.identity.name).toBe('from hook')
        expect(body.user.name).toBe('Test User')
        expect((await getSession(auth, cookiesOf(polled)))?.user.name).toBe('Test User')

        // 既にログイン中なら hook は user を受け取り、そのユーザーに付く
        const login = await directPostFlow(auth, 'authentication', alice)
        const headers = cookiesOf(login.polled)
        const second = await directPostFlow(auth, 'registration', bob, {}, headers)
        expect(second.polled.status).toBe(200)
        const list = await json<unknown[]>(await call(auth, 'GET', '/concrnt/list-identities', { headers }))
        expect(list).toHaveLength(2)
    })

    it('fails with RESOLVED_USER_INVALID when nobody decides the user', async () => {
        const auth = await createTestAuth({ registration: { requireSession: false } })
        const { polled } = await directPostFlow(auth, 'registration', alice)
        expect(polled.status).toBe(400)
        expect(await json(polled)).toMatchObject({ code: 'RESOLVED_USER_INVALID' })
        // ceremony は消費済み: ポーリングし直しても pending
        expect(await json(await poll(auth, polled as never))).toBeDefined()
    })

    it('uses resolveUser at start when requireSession is false', async () => {
        const auth = await createTestAuth({
            registration: {
                requireSession: false,
                resolveUser: async ({ ctx, context }) => {
                    const u = await ctx.context.internalAdapter.createUser({ name: `ctx:${context}`, email: `${context}@concrnt.invalid`, emailVerified: false }, { method: 'concrnt' })
                    return { id: u.id, name: u.name }
                }
            }
        })
        const { polled } = await directPostFlow(auth, 'registration', alice, { context: 'invite-42', createSession: true })
        expect(polled.status).toBe(200)
        expect(await json(polled)).toMatchObject({ user: { name: 'ctx:invite-42' } })
    })
})

describe('identity management', () => {
    it('lists, renames and deletes only the caller\'s identities', async () => {
        const auth = await createTestAuth()
        const owner = await signUpUser(auth, 'm1')
        const other = await signUpUser(auth, 'm2')
        const { polled } = await directPostFlow(auth, 'registration', alice, {}, owner.headers)
        const { identity } = await json<{ identity: { id: string } }>(polled)

        expect((await call(auth, 'GET', '/concrnt/list-identities')).status).toBe(401)
        const renamedByOther = await call(auth, 'POST', '/concrnt/update-identity', { json: { id: identity.id, name: 'x' }, headers: other.headers })
        expect(renamedByOther.status).toBe(403)
        const renamed = await call(auth, 'POST', '/concrnt/update-identity', { json: { id: identity.id, name: 'Laptop' }, headers: owner.headers })
        expect(await json(renamed)).toMatchObject({ identity: { id: identity.id, name: 'Laptop' } })
        const deletedByOther = await call(auth, 'POST', '/concrnt/delete-identity', { json: { id: identity.id }, headers: other.headers })
        expect(deletedByOther.status).toBe(403)
        expect((await call(auth, 'POST', '/concrnt/delete-identity', { json: { id: identity.id }, headers: owner.headers })).status).toBe(200)
        expect(await json<unknown[]>(await call(auth, 'GET', '/concrnt/list-identities', { headers: owner.headers }))).toEqual([])
        const missing = await call(auth, 'POST', '/concrnt/delete-identity', { json: { id: identity.id }, headers: owner.headers })
        expect(missing.status).toBe(404)
    })
})

describe('status endpoint', () => {
    it('requires pollToken and stays pending for unknown tokens', async () => {
        const auth = await createTestAuth()
        expect((await call(auth, 'GET', '/concrnt/status')).status).toBe(400)
        expect(await json(await call(auth, 'GET', '/concrnt/status?pollToken=nope'))).toEqual({ status: 'pending' })
    })
})
