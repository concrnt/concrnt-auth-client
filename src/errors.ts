export type AuthErrorCode =
    | 'invalid_option' // ConcrntAuth のオプションが不正
    | 'invalid_request' // チャレンジ C が不正・期限切れ (request_uri / state)
    | 'request_used' // この要求には既に応答が受理されている (§9 手順 3: nonce は一回限り)
    | 'missing_state' // 応答に state が無い
    | 'missing_id_token' // 応答に id_token も error も無い
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
