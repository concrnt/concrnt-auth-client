import { defineErrorCodes } from '@better-auth/core/utils/error-codes'

export const CONCRNT_ERROR_CODES = defineErrorCodes({
    /** nonce に対応する要求が無い・期限切れ・応答済み (応答を受理した要求の行は消えるので、以後は同じ扱いになる) */
    REQUEST_NOT_FOUND: 'Unknown, expired or already answered request',
    /** 検証を通った応答が同時に 2 件届き、こちらが負けた */
    REQUEST_ALREADY_USED: 'This request has already been answered',
    MISSING_ID_TOKEN: 'id_token required',
    /** 拒否応答 (error=access_denied) に nonce が無い */
    MISSING_NONCE: 'nonce required for an error response',
    INVALID_ID_TOKEN: 'Invalid id_token',
    /** signUp: 'disabled' のとき、未登録の CCID ではログインできない */
    SIGNUP_DISABLED: 'Sign-up with Concrnt is disabled',
    /** signUp: 'confirm': このブラウザに保留中のサインアップが無い (期限切れ・使用済み・別のログインを始めた) */
    NO_PENDING_SIGNUP: 'No pending sign-up for this browser',
    /** better-auth のサインイン/紐付け処理が失敗した (message に理由) */
    UNABLE_TO_SIGN_IN: 'Unable to sign in'
})
