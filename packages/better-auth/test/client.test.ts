// クライアントプラグイン: createAuthClient の fetch を auth.handler に直結して別端末フローの一連を回す
import { createAuthClient } from 'better-auth/client'
import { describe, expect, it } from 'vitest'
import { concrntClient, type ConcrntChallenge } from '../src/client.js'
import { createTestAuth, directPost, fetchRequestObject, idTokenFor, makeIdentity, ORIGIN, requestUriOf, signUpUser, type Started, type TestAuth } from './helpers.js'

const alice = makeIdentity()

const createClient = (auth: TestAuth, cookie?: string) =>
    createAuthClient({
        baseURL: ORIGIN,
        plugins: [concrntClient()],
        fetchOptions: {
            customFetchImpl: (url, init) => {
                const headers = new Headers(init?.headers)
                headers.set('origin', ORIGIN)
                if (cookie) headers.set('cookie', cookie)
                return auth.handler(new Request(url, { ...init, headers }))
            }
        }
    })

/** Authenticator 役: QR を読んで応答する */
const answer = (auth: TestAuth, c: ConcrntChallenge, form: (ro: Awaited<ReturnType<typeof fetchRequestObject>>) => Record<string, string>) =>
    void (async () => {
        const ro = await fetchRequestObject(auth, { directPostUri: c.directPostUri } as Started)
        await directPost(auth, ro, form(ro))
    })()

describe('concrntClient', () => {
    it('signIn.concrnt hands the QR to onChallenge, polls, and resolves ok with a session', async () => {
        const auth = await createTestAuth()
        const client = createClient(auth)
        const challenges: ConcrntChallenge[] = []
        const result = await client.signIn.concrnt({
            callbackURL: '/after',
            pollIntervalMs: 20,
            onChallenge: (c) => {
                challenges.push(c)
                answer(auth, c, (ro) => ({ id_token: idTokenFor(alice, ro) }))
            }
        })
        expect(challenges).toHaveLength(1)
        expect(challenges[0]).toMatchObject({ displayCode: expect.stringMatching(/\p{Extended_Pictographic}/u) })
        expect(requestUriOf({ directPostUri: challenges[0]!.directPostUri } as Started)).toMatch(/^https:\/\/rp\.test\/api\/auth\/concrnt\/request\//)
        expect(result.error).toBeNull()
        expect(result.data).toMatchObject({ status: 'ok', callbackURL: '/after', user: { name: 'Test User' } })
    })

    it('resolves denied / expired / aborted without throwing', async () => {
        const auth = await createTestAuth()
        const client = createClient(auth)
        const denied = await client.signIn.concrnt({ pollIntervalMs: 20, onChallenge: (c) => answer(auth, c, () => ({ error: 'access_denied' })) })
        expect(denied.data).toEqual({ status: 'denied', callbackURL: '/' })

        const ac = new AbortController()
        const aborted = await client.signIn.concrnt({ pollIntervalMs: 20, signal: ac.signal, onChallenge: () => setTimeout(() => ac.abort(), 30) })
        expect(aborted.data).toEqual({ status: 'aborted' })

        // 期限切れは短い TTL の RP で (exp は秒単位なので、最短で即座に切れる)
        const shortLived = createClient(await createTestAuth({ requestTtl: 1 }))
        const expired = await shortLived.signIn.concrnt({ pollIntervalMs: 100 })
        expect(expired.data).toEqual({ status: 'expired' })
    })

    it("signIn.concrnt resolves signup_required under signUp: 'confirm', and concrnt.signUp() creates the user", async () => {
        const auth = await createTestAuth({ signUp: 'confirm' })
        // customFetchImpl で cookie を持ち回る簡易ブラウザ
        let jar = ''
        const client = createAuthClient({
            baseURL: ORIGIN,
            plugins: [concrntClient()],
            fetchOptions: {
                customFetchImpl: async (url, init) => {
                    const headers = new Headers(init?.headers)
                    headers.set('origin', ORIGIN)
                    if (jar) headers.set('cookie', jar)
                    const res = await auth.handler(new Request(url, { ...init, headers }))
                    const pairs = res.headers.getSetCookie().map((line) => line.split(';')[0]!.trim())
                    if (pairs.length) jar = pairs.filter((kv) => !/=$/.test(kv)).join('; ')
                    return res
                }
            }
        })
        const held = await client.signIn.concrnt({ pollIntervalMs: 20, onChallenge: (c) => answer(auth, c, (ro) => ({ id_token: idTokenFor(alice, ro) })) })
        expect(held.data).toMatchObject({ status: 'signup_required', profile: { ccid: alice.ccid, name: 'Test User' } })
        expect((await client.concrnt.pendingSignUp()).data).toMatchObject({ profile: { ccid: alice.ccid } })
        const created = await client.concrnt.signUp()
        expect(created.error).toBeNull()
        expect(created.data).toMatchObject({ status: 'ok', isNewUser: true })
        expect((await client.getSession()).data?.user.name).toBe('Test User')
        expect((await client.concrnt.pendingSignUp()).data).toEqual({ profile: null })
    })

    it('concrnt.link requires a session and adds the CCID to that user', async () => {
        const auth = await createTestAuth()
        const anon = await createClient(auth).concrnt.link({ onChallenge: () => {} })
        expect(anon.error?.code).toBe('SESSION_REQUIRED')

        const owner = await signUpUser(auth)
        const client = createClient(auth, owner.headers.get('cookie')!)
        const linked = await client.concrnt.link({ pollIntervalMs: 20, onChallenge: (c) => answer(auth, c, (ro) => ({ id_token: idTokenFor(alice, ro) })) })
        expect(linked.error).toBeNull()
        expect(linked.data).toMatchObject({ status: 'ok', user: { id: owner.user.id } })
        const accounts = await client.listAccounts()
        expect(accounts.data?.map((a) => a.providerId).sort()).toEqual(['concrnt', 'credential'])
    })
})
