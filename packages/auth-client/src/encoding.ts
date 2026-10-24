// バイト列とテキストの変換と乱数。暗号的な処理 (ID Token の検証) は verify.ts にある
import { base64urlnopad } from '@scure/base'

export const base64urlEncode = (bytes: Uint8Array): string => base64urlnopad.encode(bytes)
export const base64urlDecode = (input: string): Uint8Array => base64urlnopad.decode(input)

export const utf8Bytes = (s: string): Uint8Array<ArrayBuffer> => new TextEncoder().encode(s)
export const utf8String = (bytes: Uint8Array): string => new TextDecoder().decode(bytes)

/** 推測困難なランダム値 (base64url) */
export const randomToken = (bytes: number): string => base64urlEncode(crypto.getRandomValues(new Uint8Array(bytes)))

/** SHA-256 を base64url で。pollToken から結果の宛先 (pollHash) を作るのに使う */
export const sha256Base64url = async (value: string): Promise<string> =>
    base64urlEncode(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8Bytes(value))))
