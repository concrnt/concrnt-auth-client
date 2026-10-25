// CIP-17 §9: RP による ID Token の検証。
// Concrnt サーバーには一切問い合わせず、署名から CCID を復元して照合する。
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { ripemd160 } from '@noble/hashes/legacy.js'
import { bech32 } from '@scure/base'
import type { IdTokenClaims } from './types.js'
import { base64urlDecode, utf8String } from './encoding.js'

/** §7.2: ID Token の有効期間 (秒)。exp = iat + ID_TOKEN_LIFETIME に固定 */
export const ID_TOKEN_LIFETIME = 300

export interface VerifyIdTokenOptions {
    /**
     * 期待する aud = 発行した送り先 URL ("https://" + <host>/<path>)。正規化せずバイト単位で一致すること (§7.2)。
     * ConcrntAuth.audience、または audienceOf(redirectUri)
     */
    audience: string
    /** この要求の nonce (= 要求の行のキー) */
    nonce: string
    /** 現在時刻 (UNIX 秒)。既定は Date.now() */
    now?: number
    /** 時計ずれの許容幅 (秒)。exp の判定と iat が未来でないことの判定に使う (§9 手順 5)。既定 300 */
    clockSkew?: number
}

/** §9 の手順 1・3〜6 をそのままの順で実装 (手順 2 の行の検索と手順 7 の消費は呼び出し側)。失敗は Error を throw、成功したらクレームを返す */
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

    // 手順3: aud が送り先 URL と完全一致する。オリジンだけ・末尾スラッシュ・オープンリダイレクタ経由のパスはここで落ちる
    if (claims.aud !== options.audience) throw new Error('aud mismatch')

    // 手順2 の続き: nonce が行の nonce と一致する (行を引くために payload を先読みしているので通常は一致する)
    if (claims.nonce !== options.nonce) throw new Error('nonce mismatch')

    // 手順4: sub == iss で、CCID (小文字 Bech32、HRP "con"、42文字) であること。
    //        CIP-2 の auth token は sub が "concrnt" なのでここで弾かれる (§7.4)
    if (typeof claims.sub !== 'string' || claims.sub !== claims.iss) throw new Error('sub must equal iss')
    if (!/^con1[a-z0-9]{38}$/.test(claims.sub)) throw new Error('sub is not a CCID')

    // 手順5: iat/exp は数値 (NumericDate。CIP-2 の文字列とは異なる §7.2)、exp = iat + 300 固定、
    //        現在時刻が exp 以内 (時計ずれ許容込み)、iat が未来でない
    if (typeof claims.iat !== 'number' || typeof claims.exp !== 'number') throw new Error('iat and exp must be numbers')
    if (claims.exp !== claims.iat + ID_TOKEN_LIFETIME) throw new Error(`exp must be iat + ${ID_TOKEN_LIFETIME}`)
    if (now >= claims.exp + clockSkew) throw new Error('token expired')
    if (claims.iat > now + clockSkew) throw new Error('iat in the future')

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

/**
 * §9 手順 2: 署名検証の前に、要求の行を引くためだけに id_token の payload の nonce を読む。
 * 検証は行を引いた後に verifyIdToken で行う。JWT の形でない・payload が読めない・nonce が無ければ null
 */
export const peekIdTokenNonce = (token: string): string | null => {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    try {
        const payload = JSON.parse(utf8String(decodeUnpadded(parts[1]!))) as { nonce?: unknown }
        return typeof payload.nonce === 'string' && payload.nonce !== '' ? payload.nonce : null
    } catch {
        return null
    }
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
