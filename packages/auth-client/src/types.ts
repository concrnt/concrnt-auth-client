// CIP-17 (Sign-In with Concrnt) の RP 側で使う型。節番号は CIP-17 本文のもの。

/**
 * §8: 応答の配送方法 (Authorization Request URI の <type>)。
 *   post:     Authenticator が送り先 URL に form POST する (別端末・QR)
 *   fragment: Authenticator が送り先 URL + "#id_token=…" を開く (同一端末・リンク)
 * どちらを使うかはブラウザ (RP のフロント) が決め、RP のサーバーは関知しない
 */
export type ResponseMode = 'post' | 'fragment'

export const RESPONSE_MODES: readonly ResponseMode[] = ['post', 'fragment']

export const isResponseMode = (value: unknown): value is ResponseMode =>
    typeof value === 'string' && (RESPONSE_MODES as readonly string[]).includes(value)

/** §7.2 / §7.3 の ID Token クレーム。RP が認識しないクレームは無視する (§7.2) */
export interface IdTokenClaims {
    iss: string
    sub: string
    /** 送り先 URL ("https://" + <rest>。n / s / RP のクエリ込み) そのもの。オリジンではない (§7.2) */
    aud: string
    nonce: string
    iat: number
    /** 常に iat + 300 (§7.2) */
    exp: number
    jti: string
    concrnt_domain: string
    // s に profile が含まれる (省略時も含む) ときだけ入る。Authenticator の自己申告なので表示専用 (§7.3)
    name?: string
    picture?: string
    profile?: string
    preferred_username?: string
    updated_at?: number
}

/** start() の結果。そのままブラウザに返してよい。応答方式には依存しない */
export interface StartedLogin {
    /** QR にする Authorization Request URI (concrnt-auth://post/<rest>)。別端末の Authenticator が読む (§8.1) */
    postUri: string
    /** 同一端末で開くリンク (concrnt-auth://fragment/<rest>)。同じ端末のアプリが開く (§8.2) */
    fragmentUri: string
    /** display_code = emojihash(n) (付録 A)。同意画面 (post) と見比べる絵文字 */
    displayCode: string
    /** 要求の行の失効時刻 (UNIX 秒)。ブラウザが QR を作り直す目安。URI には載らない */
    exp: number
    /**
     * 開始したブラウザだけが知る秘密 (§8.1)。QR には載せない。別端末フローの結果の回収 (pollResult) に使う
     */
    pollToken: string
}

/**
 * §8.1 / §8.2 / §8.3: Authenticator からの応答パラメータ。form (post) でもフラグメント (fragment) でも同じ形。
 * どの要求への応答かは id_token の payload の nonce、または拒否応答の nonce パラメータで決まる
 */
export interface AuthorizationResponseParams {
    id_token?: string | null
    error?: string | null
    /** 拒否応答 (error=access_denied) のときの要求の nonce。id_token があるときは payload から読むので不要 */
    nonce?: string | null
}

/**
 * 検証済みのログイン結果。context は start() に渡した要求ごとの付帯情報 (開始したユーザー・戻り先 URL など) がそのまま戻る
 */
export type LoginResult<T = undefined> =
    | { status: 'ok'; claims: IdTokenClaims; idToken: string; context: T }
    | { status: 'denied'; context: T }
