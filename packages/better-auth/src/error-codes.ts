import { defineErrorCodes } from '@better-auth/core/utils/error-codes'

export const CONCRNT_ERROR_CODES = defineErrorCodes({
    /** チャレンジ C が不正・期限切れ・応答済み (応答を受理した要求の行は消えるので、以後は同じ扱いになる) */
    CHALLENGE_NOT_FOUND: 'Unknown, expired or already answered request',
    /** 検証を通った応答が同時に 2 件届き、こちらが負けた */
    CHALLENGE_ALREADY_USED: 'This request has already been answered',
    MISSING_ID_TOKEN: 'id_token required',
    INVALID_ID_TOKEN: 'Invalid id_token',
    /** link: true の開始にはセッションが要る */
    SESSION_REQUIRED: 'Session required',
    /** 紐付けの ceremony は、開始したセッションを持つブラウザだけが完了できる */
    LINK_SESSION_MISMATCH: 'This link request must be completed by the session that started it',
    /** disableSignUp のとき、未登録の CCID ではログインできない */
    SIGNUP_DISABLED: 'Sign-up with Concrnt is disabled',
    /** better-auth のサインイン/紐付け処理が失敗した (message に理由) */
    UNABLE_TO_SIGN_IN: 'Unable to sign in'
})
