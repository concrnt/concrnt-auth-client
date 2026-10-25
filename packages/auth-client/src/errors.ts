export type AuthErrorCode =
    | 'invalid_option' // ConcrntAuth のオプションが不正
    | 'invalid_request' // nonce に対応する要求が無い・期限切れ・応答済み
    | 'request_used' // この要求には既に応答が受理されている (§9 手順 7: nonce は一回限り)
    | 'missing_id_token' // 応答に id_token も error も無い
    | 'missing_nonce' // 拒否応答 (error=access_denied) に nonce が無い
    | 'invalid_id_token' // ID Token の検証失敗 (§9)

/** ライブラリが投げる例外。status は RP が HTTP で返すときの目安 */
export class AuthError extends Error {
    readonly code: AuthErrorCode
    readonly status: number

    constructor(code: AuthErrorCode, message: string, status: number) {
        super(message)
        this.name = 'AuthError'
        this.code = code
        this.status = status
    }
}
