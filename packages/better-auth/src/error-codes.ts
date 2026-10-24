import { defineErrorCodes } from '@better-auth/core/utils/error-codes'

export const CONCRNT_ERROR_CODES = defineErrorCodes({
    /** チャレンジ C が不正・期限切れ・応答済み (応答を受理した要求の行は消えるので、以後は同じ扱いになる) */
    CHALLENGE_NOT_FOUND: 'Unknown, expired or already answered request',
    /** 検証を通った応答が同時に 2 件届き、こちらが負けた */
    CHALLENGE_ALREADY_USED: 'This request has already been answered',
    MISSING_ID_TOKEN: 'id_token required',
    INVALID_ID_TOKEN: 'Invalid id_token',
    /** signUp: 'disabled' のとき、未登録の CCID ではログインできない */
    SIGNUP_DISABLED: 'Sign-up with Concrnt is disabled',
    /** signUp: 'confirm': このブラウザに保留中のサインアップが無い (期限切れ・使用済み・別のログインを始めた) */
    NO_PENDING_SIGNUP: 'No pending sign-up for this browser',
    /** better-auth のサインイン/紐付け処理が失敗した (message に理由) */
    UNABLE_TO_SIGN_IN: 'Unable to sign in'
})
