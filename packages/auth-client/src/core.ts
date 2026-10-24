// CIP-17 (Sign-In with Concrnt) の RP (Relying Party) 側コア。HTTP フレームワークには依存せず、
// 利用側はルーティングとログイン後のセッションだけを自分で組む。
//
//   ブラウザ (RP フロント)        RP サーバー (このクラスの利用側)            Authenticator (world-app)
//   ---------------------        -------------------------------            -------------------------
//   ログイン開始 --------------> start()                   要求の行を置き、QR 用とリンク用の URI と pollToken を返す
//   QR (direct_post) / リンク (fragment) に
//                                                          <-QR/link-- GET  request_uri      → getRequestObject(C)
//   --- 別端末 (direct_post, §8.1) ---
//                                                          <----------- POST redirect_uri    → receiveDirectPost(C, params) → 結果を預ける
//   ポーリング ----------------> pollResult(pollToken)     結果を回収する。利用側がこのブラウザにセッションを発行する
//   --- 同一端末 (fragment, §8.2) ---
//   redirect_uri#id_token=… で開かれたブラウザが
//   フラグメントを送る --------> exchange(C, params)       検証して結果を返す。利用側がこの呼び出し元にセッションを発行する
//
// 応答方式 (§8) を選ぶのはブラウザで、サーバーは関知しない。受け口の役割が固定されているので判定も要らない:
//   redirect_uri への POST は「開始した人のために預かる」(叩いた側には何も発行しない)
//   exchange は「提示した人をログインさせる」(預け先には触らない)
// redirect_uri は要求ごとに異なり (末尾が C)、応答がどの要求のものかは届いた URL で決まる。応答パラメータに state は無い
//
// 状態は AuthStore の行だけ。要求ごとに 1 行 (`concrnt-auth:request:<C>`) を置き、応答を受理するときに原子的に消費する
// (= §9 手順 3 の nonce 一回限り)。別端末フローの結果は `concrnt-auth:result:<H(pollToken)>` に置き、開始したブラウザが
// pollToken で原子的に取り出す。秘密鍵は要らない
import { AuthError } from './errors.js'
import { emojihash } from './emojihash.js'
import { randomToken, sha256Base64url } from './encoding.js'
import type { AuthStore } from './store.js'
import {
    RESPONSE_MODES,
    type AuthorizationResponseParams,
    type ClientMetadata,
    type LoginResult,
    type RequestObject,
    type ResponseMode,
    type StartedLogin
} from './types.js'
import { verifyIdToken } from './verify.js'

export interface ConcrntAuthOptions {
    /**
     * RP のオリジン (§5.1)。`scheme://host[:port]`、末尾スラッシュ無し。request_uri / redirect_uri のオリジンであり、
     * ID Token の aud と比較する値。Authorization Request URI には host しか載らず https が暗黙なので、
     * https 以外は Authenticator から到達できない (ローカル開発用に http://localhost だけ許す)
     */
    origin: string
    /** 要求の行と別端末フローの結果を置く */
    store: AuthStore
    /** request_uri のパス。`${origin}${requestPath}/${C}` が request_uri になる。既定 `/auth/request` */
    requestPath?: string
    /** 応答の送り先 (§5.3 redirect_uri) のパス。`${origin}${redirectPath}/${C}` が redirect_uri になる。既定 `/auth/callback` */
    redirectPath?: string
    /** §5.3 client_metadata。同意画面に表示される */
    clientMetadata?: ClientMetadata
    /** Request Object の有効期間 (秒)。§5.3 は「数分程度」を推奨。既定 300 */
    requestTtl?: number
    /** ID Token の iat 判定の許容幅 (秒)。既定 300 */
    clockSkew?: number
    /** 現在時刻 (UNIX 秒) の供給元。テスト用。既定 Date.now() */
    now?: () => number
}

const REQUEST_PREFIX = 'concrnt-auth:request:'
const RESULT_PREFIX = 'concrnt-auth:result:'
/** 別端末フローの結果を、要求の失効後も回収できる猶予 (秒) */
const RESULT_GRACE = 60

/** 要求ごとの行。応答を受理するときに消費される */
interface PendingRequest<T> {
    nonce: string
    exp: number
    /** 開始したブラウザの秘密 pollToken の SHA-256。別端末フローの結果の宛先 */
    pollHash: string
    context: T
}

export class ConcrntAuth<T = undefined> {
    readonly origin: string
    readonly host: string
    readonly requestPath: string
    readonly redirectPath: string
    readonly requestTtl: number

    private readonly store: AuthStore
    private readonly clientMetadata: ClientMetadata | undefined
    private readonly clockSkew: number
    private readonly now: () => number

    constructor(options: ConcrntAuthOptions) {
        this.origin = normalizeOrigin(options.origin)
        this.host = new URL(this.origin).host
        this.store = options.store
        this.requestPath = normalizePath(options.requestPath ?? '/auth/request', 'requestPath')
        this.redirectPath = normalizePath(options.redirectPath ?? '/auth/callback', 'redirectPath')
        this.clientMetadata = options.clientMetadata
        this.requestTtl = options.requestTtl ?? 300
        this.clockSkew = options.clockSkew ?? 300
        this.now = options.now ?? (() => Math.floor(Date.now() / 1000))
    }

    /**
     * §5: Authorization Request を発行する。要求の行を 1 つ置き、両方の応答方式の URI を返す。
     * context は要求ごとの付帯情報 (開始したユーザー、戻り先 URL など) で、結果と一緒にそのまま戻る
     */
    async start(context: T): Promise<StartedLogin>
    async start(this: ConcrntAuth<undefined>): Promise<StartedLogin>
    async start(context?: T): Promise<StartedLogin> {
        const challenge = randomToken(16)
        const pollToken = randomToken(32) // ブラウザだけが知る秘密 (§8.1)。QR には含めない
        const exp = this.now() + this.requestTtl
        const request: PendingRequest<T> = { nonce: randomToken(32), exp, pollHash: await sha256Base64url(pollToken), context: context as T }
        await this.store.put(REQUEST_PREFIX + challenge, JSON.stringify(request), exp)
        const requestUri = `${this.origin}${this.requestPath}/${challenge}`
        return {
            challenge,
            requestUri,
            // 応答方式を選ぶのはブラウザ (§8)。QR には direct_post、同一端末で開くリンクには fragment
            directPostUri: authorizationRequestUri(requestUri, 'direct_post'),
            fragmentUri: authorizationRequestUri(requestUri, 'fragment'),
            displayCode: emojihash(challenge),
            exp,
            pollToken
        }
    }

    /** §5.3: Request Object。応答方式に依存しない。要求が無い・期限切れなら invalid_request (404) */
    async getRequestObject(challenge: string): Promise<RequestObject> {
        const request = await this.findRequest(challenge)
        return {
            // 要求ごとの URL。応答はここに届くので、これだけで要求を復元できる (state は使わない)
            redirect_uri: this.redirectUriFor(challenge),
            response_type: 'id_token',
            scope: 'openid profile',
            nonce: request.nonce,
            exp: request.exp,
            // §5.3 display_code: 常に付ける。Authenticator は direct_post のときだけ同意画面に出す (§6)
            display_code: emojihash(challenge),
            ...(this.clientMetadata ? { client_metadata: this.clientMetadata } : {})
        }
    }

    /** §5.3 redirect_uri: `${origin}${redirectPath}/${C}` */
    redirectUriFor(challenge: string): string {
        return `${this.origin}${this.redirectPath}/${challenge}`
    }

    /**
     * §8.1: redirect_uri に届いた応答 (別端末の Authenticator からの direct_post)。challenge は届いた URL の末尾。
     * 検証して要求を消費し、開始したブラウザが pollResult で回収できる場所に結果を置く。
     * 叩いてきた相手にセッションを発行してはならないので、結果は返さない。
     * 失敗は AuthError (invalid_request / request_used / missing_id_token / invalid_id_token)
     */
    async receiveDirectPost(challenge: string, params: AuthorizationResponseParams): Promise<void> {
        const { request, result } = await this.accept(challenge, params)
        await this.store.put(RESULT_PREFIX + request.pollHash, JSON.stringify(result), request.exp + RESULT_GRACE)
    }

    /**
     * §8.2: redirect_uri#id_token=… で開かれたブラウザが、フラグメントの内容をそのまま提示してきたもの。
     * challenge は開かれた URL (redirect_uri) の末尾。検証して要求を消費し、結果を返す。
     * 呼び出し元 (提示したブラウザ) にセッションを発行するのは利用側の仕事。開始したブラウザには何も届かない。
     * 失敗は AuthError (invalid_request / request_used / missing_id_token / invalid_id_token)
     */
    async exchange(challenge: string, params: AuthorizationResponseParams): Promise<LoginResult<T>> {
        return (await this.accept(challenge, params)).result
    }

    /**
     * §8.1: 開始したブラウザが QR に含まれない秘密 (pollToken) で結果を受け取る。原子的に取り出すので 1 回だけ返る。
     * 無ければ null (まだ応答が無い、または期限切れ。期限切れはブラウザが exp で判断する)
     */
    async pollResult(pollToken: string): Promise<LoginResult<T> | null> {
        const stored = await this.store.consume(RESULT_PREFIX + (await sha256Base64url(pollToken)))
        return stored === null ? null : (JSON.parse(stored) as LoginResult<T>)
    }

    private async findRequest(challenge: string): Promise<PendingRequest<T>> {
        const stored = await this.store.get(REQUEST_PREFIX + challenge)
        if (stored === null) throw new AuthError('invalid_request', 'unknown, expired or already answered request', 404)
        const request = JSON.parse(stored) as PendingRequest<T>
        if (request.exp <= this.now()) throw new AuthError('invalid_request', 'unknown, expired or already answered request', 404)
        return request
    }

    /**
     * §8.1 / §8.2 共通: 届いた URL の C の要求を引き、ID Token を検証 (§9) または拒否応答 (§8.3) を読み、
     * 要求の行を原子的に消費する (§9 手順 3: nonce は一回限り。QR とリンクは同じ要求なので片方で成立すればもう片方も使えない)。
     * 検証に失敗した応答は消費しない
     */
    private async accept(challenge: string, params: AuthorizationResponseParams): Promise<{ request: PendingRequest<T>; result: LoginResult<T> }> {
        const request = await this.findRequest(challenge)
        let result: LoginResult<T>
        if (params.error === 'access_denied') {
            // §8.3: ユーザーが拒否した場合のエラー応答
            result = { status: 'denied', context: request.context }
        } else {
            const idToken = params.id_token
            if (typeof idToken !== 'string' || idToken === '') throw new AuthError('missing_id_token', 'id_token required', 400)
            try {
                const claims = verifyIdToken(idToken, { origin: this.origin, nonce: request.nonce, now: this.now(), clockSkew: this.clockSkew })
                result = { status: 'ok', claims, idToken, context: request.context }
            } catch (e) {
                throw new AuthError('invalid_id_token', `invalid id_token: ${(e as Error).message}`, 400)
            }
        }
        if ((await this.store.consume(REQUEST_PREFIX + challenge)) === null) {
            throw new AuthError('request_used', 'this request has already been answered', 400)
        }
        return { request, result }
    }
}

/**
 * §5.2: request_uri (https://<host>/<path>) を Authorization Request URI concrnt-auth://<response_mode>/<host>/<path> にする。
 * start() が両方式の URI を返すので通常は呼ばなくてよい
 */
export const authorizationRequestUri = (requestUri: string, mode: ResponseMode): string => {
    if (!RESPONSE_MODES.includes(mode)) throw new AuthError('invalid_option', `unknown response_mode: ${mode}`, 500)
    const prefix = 'https://'
    if (!requestUri.startsWith(prefix)) throw new AuthError('invalid_option', `request_uri must be https: ${requestUri}`, 500)
    return `concrnt-auth://${mode}/${requestUri.slice(prefix.length)}`
}

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
    return { id_token: pick('id_token'), error: pick('error') }
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
