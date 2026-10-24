// CIP-17 §9: RP による ID Token の検証。
// Concrnt サーバーには一切問い合わせず、署名から CCID を復元して照合する。
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { ripemd160 } from '@noble/hashes/legacy.js'
import { bech32 } from '@scure/base'
import type { IdTokenClaims } from './types.js'
import { base64urlDecode, utf8String } from './encoding.js'

export interface VerifyIdTokenOptions {
    /** 自身のオリジン (§5.1: scheme://host[:port]、末尾スラッシュ無し)。aud と一致すること */
    origin: string
    /** この要求のために発行した nonce */
    nonce: string
    /** 現在時刻 (UNIX 秒)。既定は Date.now() */
    now?: number
    /** iat の「妥当な範囲」(§9 手順5) の許容幅 (秒)。既定 300 */
    clockSkew?: number
}

/** §9 の手順 1〜6 をそのままの順で実装。失敗は Error を throw、成功したらクレームを返す */
export const verifyIdToken = (token: string, options: VerifyIdTokenOptions): IdTokenClaims => {
    const now = options.now ?? Math.floor(Date.now() / 1000)
    const clockSkew = options.clockSkew ?? 300

    // 手順1: JWT として構文解析し、ヘッダーを確認する
    const parts = token.split('.')
    if (parts.length !== 3) throw new Error('malformed JWT')
    const [headerB64, payloadB64, signatureB64] = parts as [string, string, string]

    const header = JSON.parse(utf8String(decodeUnpadded(headerB64)))
    if (header.alg !== 'CONCRNT') throw new Error('alg must be CONCRNT')
    if (header.typ !== 'JWT') throw new Error('typ must be JWT')
    // kid があればサブキー署名。ID Token は master key 署名のみ (§7.1)
    if ('kid' in header) throw new Error('kid is not allowed')

    const claims = JSON.parse(utf8String(decodeUnpadded(payloadB64))) as IdTokenClaims

    // 手順2: aud が自身のオリジンと一致する
    if (claims.aud !== options.origin) throw new Error('aud mismatch')

    // 手順3: nonce が自身の発行した未使用の値と一致する (使用済みにする処理は呼び出し側が担当)
    if (claims.nonce !== options.nonce) throw new Error('nonce mismatch')

    // 手順4: sub == iss で、CCID (小文字 Bech32、HRP "con"、42文字) であること。
    //        CIP-2 の auth token は sub が "concrnt" なのでここで弾かれる (§7.4)
    if (typeof claims.sub !== 'string' || claims.sub !== claims.iss) throw new Error('sub must equal iss')
    if (!/^con1[a-z0-9]{38}$/.test(claims.sub)) throw new Error('sub is not a CCID')

    // 手順5: 有効期限。iat/exp は数値 (NumericDate)。CIP-2 の文字列とは異なる (§7.2)
    if (typeof claims.exp !== 'number' || claims.exp <= now) throw new Error('token expired')
    if (typeof claims.iat !== 'number' || Math.abs(claims.iat - now) > clockSkew) throw new Error('iat out of range')

    // 手順6: 署名から公開鍵を復元し、CCID を導出して sub と比較する
    const messageHash = keccak_256(new TextEncoder().encode(`${headerB64}.${payloadB64}`))

    // 署名は r(32) || s(32) || v(1) の 65 バイト (CIP-2 §4)。v は 0/1 (27/28 も正規化して受理可)
    const signature = decodeUnpadded(signatureB64)
    if (signature.length !== 65) throw new Error('signature must be 65 bytes')
    let v = signature[64]!
    if (v === 27 || v === 28) v -= 27
    if (v !== 0 && v !== 1) throw new Error('invalid recovery id')

    // noble の "recovered" 形式は recovery id が先頭なので並べ替える
    const recoverable = new Uint8Array(65)
    recoverable[0] = v
    recoverable.set(signature.subarray(0, 64), 1)
    // メッセージは既に Keccak256 済みなので prehash: false
    const compressedPubkey = secp256k1.recoverPublicKey(recoverable, messageHash, { prehash: false })

    if (ccidFromPublicKey(compressedPubkey) !== claims.sub) throw new Error('signature does not match sub')

    return claims
}

/** CIP-0 §5.2: CCID = bech32("con", RIPEMD160(SHA256(圧縮公開鍵))) */
export const ccidFromPublicKey = (compressedPubkey: Uint8Array): string => {
    const address = ripemd160(sha256(compressedPubkey))
    return bech32.encode('con', bech32.toWords(address))
}

// パディング無し base64url (CIP-2 §4 MUST)
const decodeUnpadded = (input: string): Uint8Array => {
    if (input.includes('=')) throw new Error('base64url must not be padded')
    return base64urlDecode(input)
}
