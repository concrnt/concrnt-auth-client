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
    listAccounts,
    makeIdentity,
    ORIGIN,
    poll,
    requestUriOf,
    signUpUser,
    start
} from './helpers.js'

const alice = makeIdentity()
const bob = makeIdentity()

describe('start / request object', () => {
    it('issues both Authorization Request URIs from one request and a Request Object under basePath', async () => {
        const auth = await createTestAuth()
        const { res, started } = await start(auth)
        expect(res.status).toBe(200)
        expect(started!.directPostUri).toMatch(/^concrnt-auth:\/\/direct_post\/rp\.test\/api\/auth\/concrnt\/request\/[A-Za-z0-9_-]{22}$/)
        const C = challengeOf(started!)
        expect(started!.fragmentUri).toBe(`concrnt-auth://fragment/rp.test/api/auth/concrnt/request/${C}`)
        expect(started!.displayCode).toMatch(/\p{Extended_Pictographic}/u)
        expect(started!.pollToken).toHaveLength(43)
        expect(started!.exp).toBeGreaterThan(Date.now() / 1000 + 200)
        expect(started!).not.toHaveProperty('requestUri')

        const roRes = await call(auth, 'GET', requestUriOf(started!))
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
        expect((ro as { nonce: string }).nonce).toHaveLength(43)
        expect(ro).not.toHaveProperty('response_mode')
    })

    it('rejects unknown challenges with 404 CHALLENGE_NOT_FOUND', async () => {
        const auth = await createTestAuth()
        const res = await call(auth, 'GET', '/concrnt/request/AAAAAAAAAAAAAAAAAAAAAA')
        expect(res.status).toBe(404)
        expect(await json(res)).toMatchObject({ code: 'CHALLENGE_NOT_FOUND' })
    })

    it('validates callbackURL against trustedOrigins and echoes it on completion', async () => {
        const auth = await createTestAuth()
        expect((await start(auth, { callbackURL: 'https://evil.test/x' })).res.status).toBe(403)
        const { polled } = await directPostFlow(auth, alice, { callbackURL: 'https://app.test/done' })
        expect(await json(polled)).toMatchObject({ status: 'ok', callbackURL: 'https://app.test/done' })
        const rel = await directPostFlow(auth, alice, { callbackURL: '/after' })
        expect(await json(rel.polled)).toMatchObject({ status: 'ok', callbackURL: '/after' })
    })
})

describe('sign-in (direct_post)', () => {
    it('signs up an unknown CCID as a new user with a placeholder email and a concrnt account row', async () => {
        const auth = await createTestAuth()
        const { started, posted, polled } = await directPostFlow(auth, alice)
        expect(posted.status).toBe(204)
        expect(posted.headers.get('set-cookie')).toBeNull()
        expect(posted.headers.get('access-control-allow-origin')).toBe('*')

        expect(polled.status).toBe(200)
        expect(hasSessionCookie(polled)).toBe(true)
        const body = await json<{ status: string; token: string; user: { id: string; name: string; email: string; image: string } }>(polled)
        expect(body.status).toBe('ok')
        expect(body.token).toBeTypeOf('string')
        expect(body.user).toMatchObject({ name: 'Test User', email: `${alice.ccid}@concrnt.placeholder.invalid`, image: 'https://example.com/avatar.png' })

        const headers = cookiesOf(polled)
        expect((await getSession(auth, headers))?.user.id).toBe(body.user.id)
        expect(await listAccounts(auth, headers)).toMatchObject([{ providerId: 'concrnt', accountId: alice.ccid }])
        // 回収は 1 回限り
        expect(await json(await poll(auth, started))).toEqual({ status: 'pending' })
    })

    it('signs an existing CCID into the same user and reports isNewUser / newUserCallbackURL', async () => {
        const auth = await createTestAuth()
        const first = await json<{ user: { id: string }; isNewUser: boolean; callbackURL: string }>(
            (await directPostFlow(auth, alice, { callbackURL: '/home', newUserCallbackURL: '/welcome' })).polled
        )
        expect(first).toMatchObject({ isNewUser: true, callbackURL: '/welcome' })
        const second = await json<{ user: { id: string }; isNewUser: boolean; callbackURL: string }>(
            (await directPostFlow(auth, alice, { callbackURL: '/home', newUserCallbackURL: '/welcome' })).polled
        )
        expect(second).toMatchObject({ isNewUser: false, callbackURL: '/home' })
        expect(second.user.id).toBe(first.user.id)
        // newUserCallbackURL も trustedOrigins で検証される
        expect((await start(auth, { newUserCallbackURL: 'https://evil.test/x' })).res.status).toBe(403)
    })

    it('rejects unknown CCIDs with 403 SIGNUP_DISABLED when disableSignUp is set and creates nothing', async () => {
        const auth = await createTestAuth({ disableSignUp: true })
        const { polled } = await directPostFlow(auth, bob)
        expect(polled.status).toBe(403)
        expect(await json(polled)).toMatchObject({ code: 'SIGNUP_DISABLED' })
        expect(hasSessionCookie(polled)).toBe(false)
    })

    it('reports denied without a session', async () => {
        const auth = await createTestAuth()
        const { started } = await start(auth, { callbackURL: '/login' })
        const ro = await fetchRequestObject(auth, started!)
        expect((await directPost(auth, ro, { error: 'access_denied' })).status).toBe(204)
        const polled = await poll(auth, started!)
        expect(await json(polled)).toEqual({ status: 'denied', callbackURL: '/login' })
        expect(hasSessionCookie(polled)).toBe(false)
    })

    it('rejects replays on either route once a response is accepted (§9 step 3)', async () => {
        const auth = await createTestAuth()
        const { ro, posted, started } = await directPostFlow(auth, alice)
        expect(posted.status).toBe(204)
        const again = await directPost(auth, ro, { id_token: idTokenFor(alice, ro) })
        expect(again.status).toBe(404)
        expect(await json(again)).toMatchObject({ code: 'CHALLENGE_NOT_FOUND' })
        const viaFragment = await exchange(auth, ro, { id_token: idTokenFor(alice, ro) })
        expect(viaFragment.status).toBe(404)
        expect(hasSessionCookie(viaFragment)).toBe(false)
        expect((await call(auth, 'GET', requestUriOf(started))).status).toBe(404)
    })

    it('accepts exactly one of two concurrent valid responses (atomic consume)', async () => {
        const auth = await createTestAuth()
        const { started } = await start(auth)
        const ro = await fetchRequestObject(auth, started!)
        const results = await Promise.all([directPost(auth, ro, { id_token: idTokenFor(alice, ro) }), directPost(auth, ro, { id_token: idTokenFor(alice, ro) })])
        expect(results.map((r) => r.status).sort()).toEqual([204, 400])
        expect(await json(results.find((r) => r.status === 400)!)).toMatchObject({ code: 'CHALLENGE_ALREADY_USED' })
    })

    it('does not consume the request on invalid or missing id_token', async () => {
        const auth = await createTestAuth()
        const { started } = await start(auth)
        const ro = await fetchRequestObject(auth, started!)
        const missing = await directPost(auth, ro, { foo: 'bar' })
        expect(missing.status).toBe(400)
        expect(await json(missing)).toMatchObject({ code: 'MISSING_ID_TOKEN' })
        const wrongAud = await directPost(auth, ro, { id_token: idTokenFor(alice, ro, { claims: { aud: 'https://other.test' } }) })
        expect(wrongAud.status).toBe(400)
        expect(await json(wrongAud)).toMatchObject({ code: 'INVALID_ID_TOKEN' })
        const wrongNonce = await directPost(auth, ro, { id_token: idTokenFor(alice, ro, { claims: { nonce: 'x' } }) })
        expect(wrongNonce.status).toBe(400)
        const withKid = await directPost(auth, ro, { id_token: idTokenFor(alice, ro, { header: { kid: 'x' } }) })
        expect(withKid.status).toBe(400)
        expect((await directPost(auth, ro, { id_token: idTokenFor(alice, ro) })).status).toBe(204)
    })

    it('also accepts JSON bodies on the direct_post endpoint and rejects unknown media types', async () => {
        const auth = await createTestAuth()
        const { started } = await start(auth)
        const ro = await fetchRequestObject(auth, started!)
        const asText = await call(auth, 'POST', ro.redirect_uri, { headers: { 'content-type': 'text/plain' }, authenticator: true })
        expect(asText.ok).toBe(false)
        expect((await call(auth, 'POST', ro.redirect_uri, { json: { id_token: idTokenFor(alice, ro) }, authenticator: true })).status).toBe(204)
    })
})

describe('sign-in (fragment)', () => {
    it('serves the landing page at redirect_uri with a CSP that allows only its own script', async () => {
        const auth = await createTestAuth()
        const { started } = await start(auth)
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
        const owner = await json<{ user: { id: string } }>((await directPostFlow(auth, alice)).polled)
        const { started } = await start(auth, { callbackURL: '/home' })
        const ro = await fetchRequestObject(auth, started!)
        const res = await exchange(auth, ro, { id_token: idTokenFor(alice, ro), error: null })
        expect(res.status).toBe(200)
        expect(hasSessionCookie(res)).toBe(true)
        expect(await json(res)).toMatchObject({ status: 'ok', callbackURL: '/home', user: { id: owner.user.id } })
        expect((await getSession(auth, cookiesOf(res)))?.user.id).toBe(owner.user.id)
        // 開始したブラウザのポーリングには何も届かない
        expect(await json(await poll(auth, started!))).toEqual({ status: 'pending' })
    })

    it('exchange reports denied and honours disableSignUp', async () => {
        const auth = await createTestAuth({ disableSignUp: true })
        const { started } = await start(auth)
        const ro = await fetchRequestObject(auth, started!)
        const denied = await exchange(auth, ro, { error: 'access_denied' })
        expect(await json(denied)).toEqual({ status: 'denied', callbackURL: '/' })
        const s2 = (await start(auth)).started!
        const ro2 = await fetchRequestObject(auth, s2)
        const unknown = await exchange(auth, ro2, { id_token: idTokenFor(bob, ro2) })
        expect(unknown.status).toBe(403)
        expect(await json(unknown)).toMatchObject({ code: 'SIGNUP_DISABLED' })
    })
})

describe('link', () => {
    it('requires a session to start and links the CCID to that user as a second account', async () => {
        const auth = await createTestAuth()
        const anon = await start(auth, { link: true })
        expect(anon.res.status).toBe(401)
        expect(await json(anon.res)).toMatchObject({ code: 'SESSION_REQUIRED' })

        const owner = await signUpUser(auth)
        const { polled } = await directPostFlow(auth, alice, { link: true }, owner.headers)
        expect(polled.status).toBe(200)
        expect(await json(polled)).toMatchObject({ status: 'ok', user: { id: owner.user.id } })
        const accounts = await listAccounts(auth, owner.headers)
        expect(accounts.map((a) => a.providerId).sort()).toEqual(['concrnt', 'credential'])

        // 紐付けた CCID でログインすると同じユーザー
        const login = await directPostFlow(auth, alice)
        expect(await json(login.polled)).toMatchObject({ status: 'ok', user: { id: owner.user.id } })

        // 紐付け済みの CCID を別のユーザーに紐付けようとすると CONFLICT
        const other = await signUpUser(auth)
        const conflict = await directPostFlow(auth, alice, { link: true }, other.headers)
        expect(conflict.polled.status).toBe(409)
        expect(await listAccounts(auth, other.headers)).toHaveLength(1)
    })

    it('refuses to complete a link for a different or missing session, on either route', async () => {
        const auth = await createTestAuth()
        const owner = await signUpUser(auth)
        const other = await signUpUser(auth)

        // direct_post: 別人のセッション、または無セッションでポーリング
        const { started } = await start(auth, { link: true }, owner.headers)
        const ro = await fetchRequestObject(auth, started!)
        expect((await directPost(auth, ro, { id_token: idTokenFor(alice, ro) })).status).toBe(204)
        const byOther = await poll(auth, started!, other.headers)
        expect(byOther.status).toBe(401)
        expect(await json(byOther)).toMatchObject({ code: 'LINK_SESSION_MISMATCH' })
        // 結果は消費済みなので、本人がポーリングしても pending (やり直し)
        expect(await json(await poll(auth, started!, owner.headers))).toEqual({ status: 'pending' })

        // fragment: 別人、または未ログインのブラウザが提示
        const s2 = (await start(auth, { link: true }, owner.headers)).started!
        const ro2 = await fetchRequestObject(auth, s2)
        expect((await exchange(auth, ro2, { id_token: idTokenFor(alice, ro2) }, other.headers)).status).toBe(401)
        const s3 = (await start(auth, { link: true }, owner.headers)).started!
        const ro3 = await fetchRequestObject(auth, s3)
        expect((await exchange(auth, ro3, { id_token: idTokenFor(alice, ro3) })).status).toBe(401)

        // fragment: 本人が提示すれば成立
        const s4 = (await start(auth, { link: true }, owner.headers)).started!
        const ro4 = await fetchRequestObject(auth, s4)
        const byOwner = await exchange(auth, ro4, { id_token: idTokenFor(alice, ro4) }, owner.headers)
        expect(byOwner.status).toBe(200)
        expect(await json(byOwner)).toMatchObject({ status: 'ok', user: { id: owner.user.id } })
        expect(await listAccounts(auth, owner.headers)).toHaveLength(2)
    })

    it('a logged-in browser signing in (without link) switches to the CCID owner instead of linking', async () => {
        const auth = await createTestAuth()
        const owner = await json<{ user: { id: string } }>((await directPostFlow(auth, alice)).polled)
        const other = await signUpUser(auth)
        const { polled } = await directPostFlow(auth, alice, {}, other.headers)
        expect(await json(polled)).toMatchObject({ status: 'ok', user: { id: owner.user.id } })
        expect(await listAccounts(auth, other.headers)).toHaveLength(1)
    })

    it('unlinking is better-auth\'s own endpoint and refuses to remove the last account', async () => {
        const auth = await createTestAuth()
        const polled = (await directPostFlow(auth, alice)).polled
        const headers = cookiesOf(polled)
        const [account] = await listAccounts(auth, headers)
        const res = await call(auth, 'POST', '/unlink-account', { json: { accountId: account!.id }, headers })
        expect(res.status).toBe(400)
        expect(await json(res)).toMatchObject({ code: 'FAILED_TO_UNLINK_LAST_ACCOUNT' })
    })
})

describe('status endpoint', () => {
    it('requires a JSON POST with pollToken and stays pending for unknown tokens', async () => {
        const auth = await createTestAuth()
        expect((await call(auth, 'POST', '/concrnt/status', { json: {} })).status).toBe(400)
        expect(await json(await call(auth, 'POST', '/concrnt/status', { json: { pollToken: 'nope' } }))).toEqual({ status: 'pending' })
        // GET では到達できない (cross-site のトップレベル遷移でセッションを発行させない)
        const get = await auth.handler(new Request(`${ORIGIN}/api/auth/concrnt/status?pollToken=nope`))
        expect(get.ok).toBe(false)
    })

    it('cannot be reached by a cross-site HTML form (login CSRF)', async () => {
        const auth = await createTestAuth()
        const { started } = await start(auth)
        const ro = await fetchRequestObject(auth, started!)
        await directPost(auth, ro, { id_token: idTokenFor(alice, ro) })
        const form = await auth.handler(
            new Request(`${ORIGIN}/api/auth/concrnt/status`, {
                method: 'POST',
                headers: { 'content-type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({ pollToken: started!.pollToken })
            })
        )
        expect(form.status).toBe(415)
        expect(hasSessionCookie(form)).toBe(false)
        // 正規のブラウザ (JSON) なら取れる
        expect(hasSessionCookie(await poll(auth, started!))).toBe(true)
    })
})
