// クライアントプラグイン: createAuthClient の fetch を auth.handler に直結して direct_post の一連を回す
import { createAuthClient } from 'better-auth/client'
import { describe, expect, it } from 'vitest'
import { concrntClient } from '../src/client.js'
import { call, createTestAuth, directPost, directPostFlow, fetchRequestObject, idTokenFor, makeIdentity, ORIGIN, signUpUser, type Started } from './helpers.js'

const alice = makeIdentity()

describe('concrntClient', () => {
    it('signIn.concrnt (direct_post) hands the QR to onChallenge, polls, and resolves ok', async () => {
        const auth = await createTestAuth()
        const owner = await signUpUser(auth, 'owner')
        expect((await directPostFlow(auth, 'registration', alice, {}, owner.headers)).polled.status).toBe(200)

        const client = createAuthClient({
            baseURL: ORIGIN,
            plugins: [concrntClient()],
            fetchOptions: {
                customFetchImpl: (url, init) => {
                    const headers = new Headers(init?.headers)
                    headers.set('origin', ORIGIN)
                    return auth.handler(new Request(url, { ...init, headers }))
                }
            }
        })

        const challenges: unknown[] = []
        const flow = client.signIn.concrnt({
            mode: 'direct_post',
            callbackURL: '/after',
            pollIntervalMs: 20,
            onChallenge: (c) => {
                challenges.push(c)
                // Authenticator が QR を読んで応答する
                void (async () => {
                    const requestUri = `https://${c.directPostUri.slice('concrnt-auth://direct_post/'.length)}`
                    const ro = await fetchRequestObject(auth, { requestUri } as Started)
                    await directPost(auth, ro, { id_token: idTokenFor(alice, ro) })
                })()
            }
        })
        const result = await flow
        expect(challenges).toHaveLength(1)
        expect(challenges[0]).toMatchObject({ displayCode: expect.stringMatching(/\p{Extended_Pictographic}/u) })
        expect(result.error).toBeNull()
        expect(result.data).toMatchObject({ status: 'ok', callbackURL: '/after', data: { user: { id: owner.user.id } } })
    })

    it('resolves denied / expired / aborted without throwing', async () => {
        const auth = await createTestAuth()
        const client = createAuthClient({
            baseURL: ORIGIN,
            plugins: [concrntClient()],
            fetchOptions: { customFetchImpl: (url, init) => auth.handler(new Request(url, { ...init, headers: { ...Object.fromEntries(new Headers(init?.headers)), origin: ORIGIN } })) }
        })
        const denied = client.signIn.concrnt({
            pollIntervalMs: 20,
            onChallenge: (c) => {
                void (async () => {
                    const requestUri = `https://${c.directPostUri.slice('concrnt-auth://direct_post/'.length)}`
                    const ro = await fetchRequestObject(auth, { requestUri } as Started)
                    await directPost(auth, ro, { error: 'access_denied' })
                })()
            }
        })
        expect((await denied).data).toEqual({ status: 'denied', callbackURL: '/' })

        const ac = new AbortController()
        const aborted = client.signIn.concrnt({ pollIntervalMs: 20, signal: ac.signal, onChallenge: () => setTimeout(() => ac.abort(), 30) })
        expect((await aborted).data).toEqual({ status: 'aborted' })

        // 一覧は未ログインなら 401 がエラーとして返る
        const list = await client.concrnt.listIdentities()
        expect(list.error?.status).toBe(401)
        void call
    })
})
