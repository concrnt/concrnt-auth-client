import { defineErrorCodes } from '@better-auth/core/utils/error-codes'

export const CONCRNT_ERROR_CODES = defineErrorCodes({
    // @concrnt/auth-client の AuthError の写し
    CHALLENGE_NOT_FOUND: 'Unknown or expired request',
    CHALLENGE_ALREADY_USED: 'This request has already been answered',
    MISSING_ID_TOKEN: 'id_token required',
    INVALID_ID_TOKEN: 'Invalid id_token',
    INVALID_CONFIGURATION: 'Invalid concrnt plugin configuration',
    // プラグイン固有
    CEREMONY_NOT_FOUND: 'Login ceremony not found or already completed',
    SESSION_REQUIRED: 'Session required',
    RESOLVED_USER_INVALID: 'Resolved user is invalid',
    YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_IDENTITY: 'You are not allowed to register this identity',
    IDENTITY_NOT_FOUND: 'No account is linked to this Concrnt identity',
    IDENTITY_ALREADY_REGISTERED: 'This Concrnt identity is already registered',
    USER_NOT_FOUND: 'User not found',
    UNABLE_TO_CREATE_SESSION: 'Unable to create session'
})
