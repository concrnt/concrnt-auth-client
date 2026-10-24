import { describe, expect, it, vi } from 'vitest'
import { runLogin, type LoginStartResponse } from '../src/browser.js'

const started: LoginStartResponse = {
    directPostUri: 'concrnt-auth://direct_post/rp.test/auth/request/C',
    fragmentUri: 'concrnt-auth://fragment/rp.test/auth/request/C',
    displayCode: '🍣',
    exp: 1_000_300,
    pollToken: 'secret'
}

type Res = { status: 'ok'; user: string } | { status: 'denied' }

describe('runLogin', () => {
    it('hands the challenge (without pollToken) to onChallenge and polls until ok', async () => {
        let clock = 1_000_000
        const onChallenge = vi.fn()
        const responses: ({ status: 'pending' } | Res)[] = [{ status: 'pending' }, { status: 'pending' }, { status: 'ok', user: 'alice' }]
        const poll = vi.fn(async (token: string) => {
            expect(token).toBe('secret')
            return responses.shift()!
        })
        const result = await runLogin<Res>({ start: async () => started, poll, onChallenge, pollIntervalMs: 1, now: () => clock })
        expect(result).toEqual({ status: 'ok', user: 'alice' })
        expect(onChallenge).toHaveBeenCalledWith({ directPostUri: started.directPostUri, fragmentUri: started.fragmentUri, displayCode: '🍣', exp: started.exp })
        expect(poll).toHaveBeenCalledTimes(3)
    })

    it('returns denied, expired and aborted without throwing', async () => {
        expect(await runLogin<Res>({ start: async () => started, poll: async () => ({ status: 'denied' }), now: () => 1_000_000 })).toEqual({ status: 'denied' })

        let clock = 1_000_000
        const result = await runLogin<Res>({
            start: async () => started,
            poll: async () => {
                clock += 200
                return { status: 'pending' }
            },
            pollIntervalMs: 1,
            now: () => clock
        })
        expect(result).toEqual({ status: 'expired' })

        const ac = new AbortController()
        const aborted = runLogin<Res>({
            start: async () => started,
            poll: async () => {
                setTimeout(() => ac.abort(), 1)
                return { status: 'pending' }
            },
            pollIntervalMs: 10_000,
            signal: ac.signal,
            now: () => 1_000_000
        })
        expect(await aborted).toEqual({ status: 'aborted' })
    })

    it('propagates errors from start and poll', async () => {
        await expect(runLogin<Res>({ start: async () => Promise.reject(new Error('start failed')), poll: async () => ({ status: 'denied' }) })).rejects.toThrow('start failed')
        await expect(runLogin<Res>({ start: async () => started, poll: async () => Promise.reject(new Error('poll failed')), now: () => 1_000_000 })).rejects.toThrow('poll failed')
    })
})
