// CIP-17 (Sign-In with Concrnt) の RP 側で使う型。節番号は CIP-17 本文のもの。

/**
 * §8: 応答の配送方法。Authorization Request URI の <response_mode> にだけ載り、Request Object には含まれない。
 * どちらを使うかはブラウザ (RP のフロント) が決め、RP のサーバーは関知しない
 */
export type ResponseMode = 'direct_post' | 'fragment'

export const RESPONSE_MODES: readonly ResponseMode[] = ['direct_post', 'fragment']

export const isResponseMode = (value: unknown): value is ResponseMode =>
    typeof value === 'string' && (RESPONSE_MODES as readonly string[]).includes(value)

/** §5.3 client_metadata。メンバ名は OpenID Connect Dynamic Client Registration に従う */
export interface ClientMetadata {
    client_name?: string
    logo_uri?: string
    policy_uri?: string
    tos_uri?: string
}

/** §5.3 Request Object。request_uri への GET が返す JSON。応答方式に関係なく同じ内容 */
export interface RequestObject {
    redirect_uri: string
    response_type: 'id_token'
    scope: string
    nonce: string
    state: string
    exp: number
    /** 常に含める。Authenticator は direct_post のときだけ同意画面に表示する (§6) */
    display_code: string
    client_metadata?: ClientMetadata
}

/** §7.2 / §7.3 の ID Token クレーム。RP が認識しないクレームは無視する (§7.2) */
export interface IdTokenClaims {
    iss: string
    sub: string
    aud: string
    nonce: string
    iat: number
    exp: number
    jti: string
    concrnt_domain: string
    // scope=profile のときだけ入る。Authenticator の自己申告なので表示専用 (§7.3)
    name?: string
    picture?: string
    profile?: string
    preferred_username?: string
    updated_at?: number
}

/** start() の結果。応答方式には依存しない */
export interface StartedLogin {
    /**
     * ブラウザだけが知る秘密 (§8.1)。QR には載せない。別端末フローの結果の回収 (pollResult) に使う
     */
    session: string
    /** §5.3 display_code。同意画面 (direct_post) と見比べる絵文字 */
    displayCode: string
    /** 要求の失効時刻 (UNIX 秒)。RP は何も保存しないので、期限切れはブラウザ側がこれで判断する */
    exp: number
    /** チャレンジ C。request_uri のパス末尾と Request Object の state に載る */
    challenge: string
    /**
     * https://<host>/<requestPath>/<C>。ブラウザはこれを authorizationRequestUri(requestUri, mode) で
     * concrnt-auth://<mode>/<host>/<requestPath>/<C> にして QR やリンクに使う (§5.2)
     */
    requestUri: string
}

/** §8.1 / §8.2 / §8.3: Authenticator からの応答パラメータ。form (direct_post) でもフラグメント (fragment) でも同じ形 */
export interface AuthorizationResponseParams {
    state?: string | null
    id_token?: string | null
    error?: string | null
}

/** 検証済みのログイン結果 */
export type LoginResult = { status: 'ok'; claims: IdTokenClaims } | { status: 'denied' }
