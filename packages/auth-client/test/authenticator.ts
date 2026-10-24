// テスト用の最小 Authenticator: master key で CIP-17 §7 の ID Token を作る
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { base64urlnopad } from '@scure/base'
import { ccidFromPublicKey } from '../src/verify.js'
import type { RequestObject } from '../src/types.js'

export interface TestIdentity {
    privateKey: Uint8Array
    ccid: string
}

export const makeIdentity = (): TestIdentity => {
    const privateKey = secp256k1.utils.randomSecretKey()
    return { privateKey, ccid: ccidFromPublicKey(secp256k1.getPublicKey(privateKey)) }
}

const encode = (value: unknown): string => base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(value)))

/** CIP-2 §4 の r||s||v 署名 (v は 0/1) で署名した JWT */
export const signConcrntJwt = (identity: TestIdentity, header: object, payload: object, mutate?: (sig: Uint8Array) => void): string => {
    const signingInput = `${encode(header)}.${encode(payload)}`
    const recovered = secp256k1.sign(keccak_256(new TextEncoder().encode(signingInput)), identity.privateKey, {
        prehash: false,
        format: 'recovered'
    })
    const signature = new Uint8Array(65)
    signature.set(recovered.subarray(1), 0)
    signature[64] = recovered[0]!
    mutate?.(signature)
    return `${signingInput}.${base64urlnopad.encode(signature)}`
}

export interface IdTokenOverrides {
    header?: Record<string, unknown>
    claims?: Record<string, unknown>
    mutateSignature?: (sig: Uint8Array) => void
}

export const issueIdToken = (identity: TestIdentity, request: RequestObject, origin: string, now: number, overrides: IdTokenOverrides = {}): string => {
    const header = { alg: 'CONCRNT', typ: 'JWT', ...overrides.header }
    const claims = {
        iss: identity.ccid,
        sub: identity.ccid,
        aud: origin,
        nonce: request.nonce,
        iat: now,
        exp: now + 300,
        jti: crypto.randomUUID(),
        concrnt_domain: 'example.concrnt.test',
        name: 'Test User',
        picture: 'https://example.com/avatar.png',
        ...overrides.claims
    }
    return signConcrntJwt(identity, header, claims, overrides.mutateSignature)
}
