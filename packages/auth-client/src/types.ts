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
    /** 要求ごとに異なる (末尾がチャレンジ C)。応答はここに届くので、RP はこの URL で応答を要求に対応付ける */
    redirect_uri: string
    response_type: 'id_token'
    scope: string
    nonce: string
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

/** start() の結果。そのままブラウザに返してよい。応答方式には依存しない */
export interface StartedLogin {
    /** チャレンジ C。request_uri と redirect_uri のパス末尾に載る。秘密ではない */
    challenge: string
    /** https://<host>/<requestPath>/<C> */
    requestUri: string
    /** QR にする Authorization Request URI (concrnt-auth://direct_post/…)。別端末の Authenticator が読む (§8.1) */
    directPostUri: string
    /** 同一端末で開くリンク (concrnt-auth://fragment/…)。同じ端末のアプリが開く (§8.2) */
    fragmentUri: string
    /** §5.3 display_code。同意画面 (direct_post) と見比べる絵文字 */
    displayCode: string
    /** 要求の失効時刻 (UNIX 秒) */
    exp: number
    /**
     * 開始したブラウザだけが知る秘密 (§8.1)。QR には載せない。別端末フローの結果の回収 (pollResult) に使う
     */
    pollToken: string
}

/**
 * §8.1 / §8.2 / §8.3: Authenticator からの応答パラメータ。form (direct_post) でもフラグメント (fragment) でも同じ形。
 * どの要求への応答かは、応答が届いた redirect_uri (のチャレンジ C) で決まるので、パラメータには含まれない
 */
export interface AuthorizationResponseParams {
    id_token?: string | null
    error?: string | null
}

/**
 * 検証済みのログイン結果。context は start() に渡した要求ごとの付帯情報 (開始したユーザー・戻り先 URL など) がそのまま戻る
 */
export type LoginResult<T = undefined> =
    | { status: 'ok'; claims: IdTokenClaims; idToken: string; context: T }
    | { status: 'denied'; context: T }
