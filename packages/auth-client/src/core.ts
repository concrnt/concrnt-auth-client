// CIP-17 (Sign-In with Concrnt) の RP (Relying Party) 側コア。HTTP フレームワークには依存せず、
// 利用側はルーティングとログイン後のセッションだけを自分で組む。
//
//   ブラウザ (RP フロント)        RP サーバー (このクラスの利用側)            Authenticator (world-app)
//   ---------------------        -------------------------------            -------------------------
//   ログイン開始 --------------> start()                   要求の行を置き、QR 用とリンク用の URI と pollToken を返す
//   QR (post) / リンク (fragment) に         (Authenticator は URI だけで同意画面を出す。RP への取得は無い)
//   --- 別端末 (post, §8.1) ---
//                                                          <----------- POST 送り先 URL     → receivePost(params) → 結果を預ける
//   ポーリング ----------------> pollResult(pollToken)     結果を回収する。利用側がこのブラウザにセッションを発行する
//   --- 同一端末 (fragment, §8.2) ---
//   送り先 URL#id_token=… で開かれたブラウザが
//   フラグメントを送る --------> exchange(params)          検証して結果を返す。利用側がこの呼び出し元にセッションを発行する
//
// 応答方式 (§8) を選ぶのはブラウザで、サーバーは関知しない。受け口の役割が固定されているので判定も要らない:
//   送り先 URL への POST は「開始した人のために預かる」(叩いた側には何も発行しない)
//   exchange は「提示した人をログインさせる」(預け先には触らない)
// 送り先 URL は `${origin}${redirectPath}?<RP の任意クエリ>&n=<nonce>[&s=<scope>]` で、これが ID Token の aud に
// そのまま入る (§7.2。Authenticator は加工しない)。応答がどの要求のものかは id_token の payload の nonce
// (拒否応答なら nonce パラメータ) で決まる。要求の内容はすべて Authorization Request URI に載る (by-value)
//
// 状態は AuthStore の行だけ。要求ごとに 1 行 (`concrnt-auth:request:<nonce>`、aud の期待値を含む) を置き、応答を受理するときに原子的に消費する
// (= §9 手順 7 の nonce 一回限り)。別端末フローの結果は `concrnt-auth:result:<H(pollToken)>` に置き、開始したブラウザが
// pollToken で原子的に取り出す。秘密鍵は要らない
import { AuthError } from './errors.js'
import { emojihash } from './emojihash.js'
import { randomToken, sha256Base64url } from './encoding.js'
import type { AuthStore } from './store.js'
import { RESPONSE_MODES, type AuthorizationResponseParams, type LoginResult, type ResponseMode, type StartedLogin } from './types.js'
import { peekIdTokenNonce, verifyIdToken } from './verify.js'

export interface ConcrntAuthOptions {
    /**
     * RP のオリジン (`scheme://host[:port]`、末尾スラッシュ無し)。送り先 URL は `${origin}${redirectPath}`。
     * Authorization Request URI には host/path しか載らず https が暗黙なので、https 以外は Authenticator から到達できない。
     * ローカル開発用に http://localhost / 127.0.0.1 だけ許す (Authenticator は localhost へ http で送ってよい §5.2)。
     * その場合も RP の識別子 (ID Token の aud) は常に "https://" + host/path (audience)
     */
    origin: string
    /** 要求の行と別端末フローの結果を置く */
    store: AuthStore
    /** 応答の送り先 URL のパス。`${origin}${redirectPath}?…&n=<nonce>` が送り先 URL になる。クエリは持てない (start の query で渡す)。既定 `/auth/callback` */
    redirectPath?: string
    /**
     * §5.2 s: 要求する追加情報 (スペース区切り)。省略すると URI に s を付けず、"profile" を指定したものとみなされる。
     * '' (空) にすると `s=` が付き CCID だけを要求する
     */
    scope?: string
    /** 要求の行の有効期間 (秒)。Authenticator は関知しない (URI に exp は載らない)。既定 300 */
    requestTtl?: number
    /** ID Token の exp / iat 判定の時計ずれ許容幅 (秒)。既定 300 */
    clockSkew?: number
    /** 現在時刻 (UNIX 秒) の供給元。テスト用。既定 Date.now() */
    now?: () => number
}

const REQUEST_PREFIX = 'concrnt-auth:request:'
const RESULT_PREFIX = 'concrnt-auth:result:'
/** 別端末フローの結果を、要求の失効後も回収できる猶予 (秒) */
const RESULT_GRACE = 60

/** 要求ごとの行 (キーは nonce)。応答を受理するときに消費される */
interface PendingRequest<T> {
    exp: number
    /** 開始したブラウザの秘密 pollToken の SHA-256。別端末フローの結果の宛先 */
    pollHash: string
    /** ID Token の aud の期待値 = 発行した送り先 URL ("https://" + <rest>。クエリ込み)。§9 手順 3 でバイト一致を見る */
    audience: string
    context: T
}

export interface StartOptions {
    /**
     * 送り先 URL に付ける RP 自身のクエリ (§5.2)。n / s と同じクエリ文字列に混ざり、そのまま aud と応答の届く URL に入る。
     * 1 文字の名前は本仕様の予約なので使えない (invalid_option)
     */
    query?: Record<string, string>
}

export class ConcrntAuth<T = undefined> {
    readonly origin: string
    readonly redirectPath: string
    /** 応答の送り先 URL のクエリ無しの形 (RP が配信するエンドポイント)。実際の送り先はこれに `?…&n=` が付く */
    readonly redirectUri: string
    readonly requestTtl: number

    private readonly store: AuthStore
    private readonly scope: string | undefined
    private readonly clockSkew: number
    private readonly now: () => number

    constructor(options: ConcrntAuthOptions) {
        this.origin = normalizeOrigin(options.origin)
        this.store = options.store
        this.redirectPath = normalizePath(options.redirectPath ?? '/auth/callback', 'redirectPath')
        this.redirectUri = this.origin + this.redirectPath
        this.scope = options.scope
        this.requestTtl = options.requestTtl ?? 300
        this.clockSkew = options.clockSkew ?? 300
        this.now = options.now ?? (() => Math.floor(Date.now() / 1000))
    }

    /**
     * §5: Authorization Request を発行する。要求の行を 1 つ置き、両方の応答方式の URI を返す。
     * context は要求ごとの付帯情報 (開始したユーザー、戻り先 URL など) で、結果と一緒にそのまま戻る。
     * options.query は送り先 URL に付ける RP 自身のクエリ (応答の届く URL と aud にそのまま入る)
     */
    async start(context: T, options?: StartOptions): Promise<StartedLogin>
    async start(this: ConcrntAuth<undefined>, context?: undefined, options?: StartOptions): Promise<StartedLogin>
    async start(context?: T, options?: StartOptions): Promise<StartedLogin> {
        const nonce = randomToken(16) // §5.2 n: 16 バイトの乱数 (22 文字)。行のキーであり display_code の素
        const pollToken = randomToken(32) // ブラウザだけが知る秘密 (§8.1)。QR には含めない
        const exp = this.now() + this.requestTtl
        // 送り先 URL = redirectUri + RP のクエリ + n [+ s]。この文字列が (https にして) aud になる。Authenticator は加工しない
        const target = deliveryUrl(this.redirectUri, nonce, this.scope, options?.query)
        const request: PendingRequest<T> = { exp, pollHash: await sha256Base64url(pollToken), audience: audienceOf(target), context: context as T }
        await this.store.put(REQUEST_PREFIX + nonce, JSON.stringify(request), exp)
        return {
            // 応答方式を選ぶのはブラウザ (§8)。QR には post、同一端末で開くリンクには fragment。<rest> は同じ
            postUri: authorizationRequestUri(target, 'post'),
            fragmentUri: authorizationRequestUri(target, 'fragment'),
            displayCode: emojihash(nonce),
            exp,
            pollToken
        }
    }

    /**
     * §8.1: 送り先 URL に届いた応答 (別端末の Authenticator からの POST)。
     * nonce で要求を引いて検証・消費し、開始したブラウザが pollResult で回収できる場所に結果を置く。
     * 叩いてきた相手にセッションを発行してはならないので、結果は返さない。
     * 失敗は AuthError (invalid_request / request_used / missing_id_token / missing_nonce / invalid_id_token)
     */
    async receivePost(params: AuthorizationResponseParams): Promise<void> {
        const { request, result } = await this.accept(params)
        await this.store.put(RESULT_PREFIX + request.pollHash, JSON.stringify(result), request.exp + RESULT_GRACE)
    }

    /**
     * §8.2: 送り先 URL#id_token=… で開かれたブラウザが、フラグメントの内容をそのまま提示してきたもの。
     * nonce で要求を引いて検証・消費し、結果を返す。
     * 呼び出し元 (提示したブラウザ) にセッションを発行するのは利用側の仕事。開始したブラウザには何も届かない。
     * 失敗は AuthError (invalid_request / request_used / missing_id_token / missing_nonce / invalid_id_token)
     */
    async exchange(params: AuthorizationResponseParams): Promise<LoginResult<T>> {
        return (await this.accept(params)).result
    }

    /**
     * §8.1: 開始したブラウザが QR に含まれない秘密 (pollToken) で結果を受け取る。原子的に取り出すので 1 回だけ返る。
     * 無ければ null (まだ応答が無い、または期限切れ。期限切れはブラウザが exp で判断する)
     */
    async pollResult(pollToken: string): Promise<LoginResult<T> | null> {
        const stored = await this.store.consume(RESULT_PREFIX + (await sha256Base64url(pollToken)))
        return stored === null ? null : (JSON.parse(stored) as LoginResult<T>)
    }

    /** §9 手順 2: nonce で要求の行を引く。無い・期限切れ・応答済みは invalid_request (404) */
    private async findRequest(nonce: string): Promise<PendingRequest<T>> {
        const stored = await this.store.get(REQUEST_PREFIX + nonce)
        if (stored === null) throw new AuthError('invalid_request', 'unknown, expired or already answered request', 404)
        const request = JSON.parse(stored) as PendingRequest<T>
        if (request.exp <= this.now()) throw new AuthError('invalid_request', 'unknown, expired or already answered request', 404)
        return request
    }

    /**
     * §8.1 / §8.2 共通 (§9 の手順): nonce で要求を引き、ID Token を検証または拒否応答 (§8.3) を読み、
     * 要求の行を原子的に消費する (手順 7: nonce は一回限り。QR とリンクは同じ要求なので片方で成立すればもう片方も使えない)。
     * 検証に失敗した応答は消費しない
     */
    private async accept(params: AuthorizationResponseParams): Promise<{ request: PendingRequest<T>; result: LoginResult<T> }> {
        let nonce: string
        let request: PendingRequest<T>
        let result: LoginResult<T>
        if (params.error === 'access_denied') {
            // §8.3: 拒否応答は error=access_denied&nonce=<n>
            if (typeof params.nonce !== 'string' || params.nonce === '') {
                throw new AuthError('missing_nonce', 'nonce required for an error response', 400)
            }
            nonce = params.nonce
            request = await this.findRequest(nonce)
            result = { status: 'denied', context: request.context }
        } else {
            const idToken = params.id_token
            if (typeof idToken !== 'string' || idToken === '') throw new AuthError('missing_id_token', 'id_token required', 400)
            // 手順 2: 署名検証の前に payload の nonce で行を引く。検証は行を引いた後 (手順 3〜6)
            const peeked = peekIdTokenNonce(idToken)
            if (peeked === null) throw new AuthError('invalid_id_token', 'invalid id_token: malformed JWT or no nonce', 400)
            nonce = peeked
            request = await this.findRequest(nonce)
            try {
                // 手順 3: aud は発行時に保存した送り先 URL とバイト一致
                const claims = verifyIdToken(idToken, { audience: request.audience, nonce, now: this.now(), clockSkew: this.clockSkew })
                result = { status: 'ok', claims, idToken, context: request.context }
            } catch (e) {
                throw new AuthError('invalid_id_token', `invalid id_token: ${(e as Error).message}`, 400)
            }
        }
        // 手順 7: 原子的に消費
        if ((await this.store.consume(REQUEST_PREFIX + nonce)) === null) {
            throw new AuthError('request_used', 'this request has already been answered', 400)
        }
        return { request, result }
    }
}

/**
 * §5.2: 送り先 URL (クエリ無し) に RP のクエリと n [+ s] を付けて、完全な送り先 URL を作る。
 * 1 文字のパラメータ名は本仕様の予約 (RP は 2 文字以上を使う MUST)。scope を省略すると s は付かない (= "profile")。'' を渡すと `s=` (CCID のみ)
 */
export const deliveryUrl = (redirectUri: string, nonce: string, scope?: string, query?: Record<string, string>): string => {
    if (!/^[A-Za-z0-9_-]{22,}$/.test(nonce)) throw new AuthError('invalid_option', 'nonce must be base64url of at least 16 bytes', 500)
    if (redirectUri.includes('?') || redirectUri.includes('#')) {
        throw new AuthError('invalid_option', `redirect URI must not contain a query or fragment (pass RP parameters as query): ${redirectUri}`, 500)
    }
    const params = new URLSearchParams()
    for (const [key, value] of Object.entries(query ?? {})) {
        if (key.length < 2) throw new AuthError('invalid_option', `single-character query parameter names are reserved: ${key}`, 500)
        params.set(key, value)
    }
    params.set('n', nonce)
    if (scope !== undefined) params.set('s', scope)
    return `${redirectUri}?${params.toString()}`
}

/**
 * §5.2: 完全な送り先 URL (https://<rest>) から Authorization Request URI `concrnt-auth://<mode>/<rest>` を作る。
 * "https://" を外すだけで <rest> は加工しない。start() が両方式の URI を返すので通常は呼ばなくてよい
 */
export const authorizationRequestUri = (url: string, mode: ResponseMode): string => {
    if (!RESPONSE_MODES.includes(mode)) throw new AuthError('invalid_option', `unknown response type: ${mode}`, 500)
    return `concrnt-auth://${mode}/${requestTarget(url)}`
}

/** §7.2: ID Token の aud の期待値 = "https://" + <rest>。送り先 URL が http://localhost でも https 表記 */
export const audienceOf = (url: string): string => `https://${requestTarget(url)}`

/**
 * §8.1 (form) / §8.2 (フラグメント) の応答パラメータを取り出す。
 * `await request.formData()`、`new URLSearchParams(location.hash.slice(1))`、JSON body のオブジェクトをそのまま渡せる。
 * 未知のパラメータは無視する
 */
export const parseAuthorizationResponse = (source: FormData | URLSearchParams | Record<string, unknown>): AuthorizationResponseParams => {
    const pick = (name: string): string | null => {
        const value = source instanceof FormData || source instanceof URLSearchParams ? source.get(name) : source[name]
        return typeof value === 'string' ? value : null
    }
    return { id_token: pick('id_token'), error: pick('error'), nonce: pick('nonce') }
}

/**
 * 送り先 URL から URI に載せる <rest> (= スキームを外した残り。クエリ込み) を取る。https か、ローカル開発用の http://localhost / 127.0.0.1 のみ。
 * userinfo・フラグメント・空パスは拒否。正規化はしない (aud はこの文字列にバイト一致)
 */
const requestTarget = (target: string): string => {
    let url: URL
    try {
        url = new URL(target)
    } catch {
        throw new AuthError('invalid_option', `redirect URI is not a URL: ${target}`, 500)
    }
    const isLocalhost = url.hostname === 'localhost' || url.hostname === '127.0.0.1'
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLocalhost)) {
        throw new AuthError('invalid_option', `redirect URI must be https (http only for localhost): ${target}`, 500)
    }
    if (url.username || url.password) throw new AuthError('invalid_option', `redirect URI must not contain userinfo: ${target}`, 500)
    if (target.includes('#')) throw new AuthError('invalid_option', `redirect URI must not contain a fragment: ${target}`, 500)
    if (url.pathname === '/') throw new AuthError('invalid_option', `redirect URI path must not be empty: ${target}`, 500)
    return target.slice(target.indexOf('://') + 3)
}

const normalizeOrigin = (origin: string): string => {
    let url: URL
    try {
        url = new URL(origin)
    } catch {
        throw new AuthError('invalid_option', `origin is not a URL: ${origin}`, 500)
    }
    if (url.origin !== origin) {
        throw new AuthError('invalid_option', `origin must be scheme://host[:port] without path or trailing slash: ${origin}`, 500)
    }
    const isLocalhost = url.hostname === 'localhost' || url.hostname === '127.0.0.1'
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLocalhost)) {
        throw new AuthError('invalid_option', `origin must be https (Authorization Request URI implies https): ${origin}`, 500)
    }
    return url.origin
}

const normalizePath = (path: string, name: string): string => {
    if (!path.startsWith('/') || path.endsWith('/') || path.includes('?') || path.includes('#')) {
        throw new AuthError('invalid_option', `${name} must start with "/" and must not end with "/" or contain a query/fragment: ${path}`, 500)
    }
    return path
}
