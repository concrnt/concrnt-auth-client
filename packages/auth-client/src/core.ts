// CIP-17 (Sign-In with Concrnt) の RP (Relying Party) 側コア。HTTP フレームワークには依存せず、
// 利用側はルーティングとログイン後のセッションだけを自分で組む。
//
//   ブラウザ (RP フロント)        RP サーバー (このクラスの利用側)            Authenticator (world-app)
//   ---------------------        -------------------------------            -------------------------
//   ログイン開始 --------------> start()                   チャレンジ C と request_uri を返す。何も保存しない
//   requestUri を concrnt-auth://<mode>/… にして QR / リンクに
//                                                          <-QR/link-- GET  request_uri      → getRequestObject(C)
//   --- 別端末 (direct_post) ---
//                                                          <----------- POST redirect_uri    → receiveDirectPost(C, params) → mailbox
//   ポーリング ----------------> pollResult(session)       mailbox から結果を回収する
//   --- 同一端末 (fragment) ---
//   redirect_uri#id_token=… で開かれたブラウザが
//   フラグメントを送る --------> exchange(C, params)       検証して claims を返す。この呼び出し元にセッションを発行する
//
// 応答方式 (§8) を選ぶのはブラウザで、サーバーは関知しない。受け口の役割が固定されているので判定も要らない:
//   redirect_uri への POST は「開始した人のために預かる」(叩いた側には何も発行しない)
//   exchange は「提示した人をログインさせる」(mailbox には触らない)
// redirect_uri は要求ごとに異なり (末尾が C)、応答がどの要求のものかは届いた URL で決まる。応答パラメータに state は無い
//
// できるだけ状態を持たない作り: 要求は HMAC 付きチャレンジ C として Authenticator を経由して戻ってくるので保存しない。
// 残る状態は secret (HMAC 鍵) と AuthStore だけ。AuthStore には別端末フローのメールボックスと、
// 応答を受理したチャレンジの使用済み記録 (§9 手順 3) を置く。メールボックスの中身は署名済みの封筒なので、
// ストアに改ざん耐性も強整合も要らない。
import { AuthError } from './errors.js'
import { emojihash } from './emojihash.js'
import type { AuthStore } from './store.js'
import {
    base64urlEncode,
    derive,
    packChallenge,
    randomToken,
    sessionHash,
    signJwt,
    unpackChallenge,
    verifyJwt,
    type ChallengePayload
} from './token.js'
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
    /** HMAC 鍵。チャレンジの MAC、nonce の導出、メールボックスの封筒の署名に使う */
    secret: string
    /** メールボックス (§8.1) と使用済み記録 (§9 手順 3) */
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

const MAILBOX_PREFIX = 'concrnt-auth:mailbox:'
const USED_PREFIX = 'concrnt-auth:used:'
const MAILBOX_TYP = 'concrnt-auth-result+jwt'

// メールボックスに置く封筒。宛先 (sh) を含めるので、別の箱の中身を移しても pollResult で捨てられる
interface MailboxEnvelope {
    sh: string
    exp: number
    result: LoginResult
}

export class ConcrntAuth {
    readonly origin: string
    readonly host: string
    readonly requestPath: string
    readonly redirectPath: string
    readonly requestTtl: number

    private readonly secret: string
    private readonly store: AuthStore
    private readonly clientMetadata: ClientMetadata | undefined
    private readonly clockSkew: number
    private readonly now: () => number

    constructor(options: ConcrntAuthOptions) {
        this.origin = normalizeOrigin(options.origin)
        this.host = new URL(this.origin).host
        if (!options.secret) throw new AuthError('invalid_option', 'secret is required', 500)
        this.secret = options.secret
        this.store = options.store
        this.requestPath = normalizePath(options.requestPath ?? '/auth/request', 'requestPath')
        this.redirectPath = normalizePath(options.redirectPath ?? '/auth/callback', 'redirectPath')
        this.clientMetadata = options.clientMetadata
        this.requestTtl = options.requestTtl ?? 300
        this.clockSkew = options.clockSkew ?? 300
        this.now = options.now ?? (() => Math.floor(Date.now() / 1000))
    }

    /**
     * §5: Authorization Request を生成する。何も保存しない。
     * 返した requestUri をブラウザが authorizationRequestUri(requestUri, mode) で concrnt-auth:// URI にする。
     * QR 用 (direct_post) とリンク用 (fragment) は同じチャレンジから作れるので、サーバーは応答方式を知らなくてよい
     */
    start(): StartedLogin {
        const session = randomToken() // ブラウザだけが知る秘密 (§8.1)。QR には含めない
        const sh = sessionHash(session)
        const exp = this.now() + this.requestTtl
        const challenge = packChallenge({ exp, sh }, this.secret)
        return {
            session,
            displayCode: displayCodeFor(sh),
            exp,
            challenge,
            requestId: base64urlEncode(sh),
            requestUri: `${this.origin}${this.requestPath}/${challenge}`
        }
    }

    /** start() の requestId を、応答が届いた URL の C から取り出す。C が不正・期限切れなら invalid_request (404) */
    requestIdOf(challenge: string): string {
        return base64urlEncode(this.readChallenge(challenge, 404).sh)
    }

    /** start() の requestId を、開始したブラウザの秘密 (session) から求める。何も確認しない (箱の鍵と同じ計算) */
    requestIdOfSession(session: string): string {
        return base64urlEncode(sessionHash(session))
    }

    /** §5.3: Request Object。保存していないので、チャレンジ C から毎回同じものを組み立て直す。応答方式に依存しない */
    getRequestObject(challenge: string): RequestObject {
        const req = this.readChallenge(challenge, 404)
        return {
            // 要求ごとの URL。応答はここに届くので、これだけで要求を復元できる (state は使わない)
            redirect_uri: this.redirectUriFor(challenge),
            response_type: 'id_token',
            scope: 'openid profile',
            nonce: this.nonceFor(challenge), // 保存せず C から導出する。応答時に同じ計算で照合する
            exp: req.exp,
            // §5.3 display_code: 常に付ける。Authenticator は direct_post のときだけ同意画面に出す (§6)
            display_code: displayCodeFor(req.sh),
            ...(this.clientMetadata ? { client_metadata: this.clientMetadata } : {})
        }
    }

    /** §5.3 redirect_uri: `${origin}${redirectPath}/${C}` */
    redirectUriFor(challenge: string): string {
        return `${this.origin}${this.redirectPath}/${challenge}`
    }

    /**
     * §8.1: redirect_uri に届いた応答 (別端末の Authenticator からの direct_post)。challenge は届いた URL の末尾。
     * 検証して、要求を開始したブラウザが pollResult で回収できるメールボックスに置く。
     * 叩いてきた相手にセッションを発行してはならないので、結果は返さない。
     * 失敗は AuthError (invalid_request / request_used / missing_id_token / invalid_id_token)
     */
    async receiveDirectPost(challenge: string, params: AuthorizationResponseParams): Promise<void> {
        const { payload, result } = await this.accept(challenge, params)
        const sh = base64urlEncode(payload.sh)
        const envelope: MailboxEnvelope = { sh, exp: payload.exp, result }
        await this.store.set(MAILBOX_PREFIX + sh, signJwt(MAILBOX_TYP, envelope, this.secret), this.ttlUntil(payload.exp))
    }

    /**
     * §8.2: redirect_uri#id_token=… で開かれたブラウザが、フラグメントの内容をそのまま提示してきたもの。
     * challenge は開かれた URL (redirect_uri) の末尾。検証して結果を返す。
     * 呼び出し元 (提示したブラウザ) にセッションを発行するのは利用側の仕事。
     * 要求を開始したセッションには結び付けない (メールボックスには触らない)。
     * 失敗は AuthError (invalid_request / request_used / missing_id_token / invalid_id_token)
     */
    async exchange(challenge: string, params: AuthorizationResponseParams): Promise<LoginResult> {
        return (await this.accept(challenge, params)).result
    }

    /**
     * §8.1: ブラウザは QR に含まれない秘密 (session) で結果を受け取る。読んだら消す。
     * 開始時には何も記録していないので、箱が空なら「まだ」としか言えない (期限切れはブラウザが exp で判断する)。
     * ストアの中身が壊れている・偽物なら無かったものとして扱う
     */
    async pollResult(session: string): Promise<LoginResult | null> {
        const sh = base64urlEncode(sessionHash(session))
        const key = MAILBOX_PREFIX + sh
        const stored = await this.store.get(key)
        if (stored === null) return null
        await this.store.delete(key)
        try {
            const envelope = verifyJwt<MailboxEnvelope>(stored, MAILBOX_TYP, this.secret, this.now())
            if (envelope.sh !== sh) return null
            return envelope.result
        } catch {
            return null
        }
    }

    // §8.1 / §8.2 共通: 届いた URL の C を検証し、未使用であることを確認し、ID Token を検証 (§9) または拒否応答 (§8.3) を読み、
    // チャレンジを使用済みにする。QR とリンクは同じ C を共有するので、片方で成立すればもう片方も使えなくなる
    private async accept(challenge: string, params: AuthorizationResponseParams): Promise<{ payload: ChallengePayload; result: LoginResult }> {
        const payload = this.readChallenge(challenge, 404)

        const usedKey = USED_PREFIX + challenge
        if ((await this.store.get(usedKey)) !== null) throw new AuthError('request_used', 'this request has already been answered', 400)

        let result: LoginResult
        if (params.error === 'access_denied') {
            // §8.3: ユーザーが拒否した場合のエラー応答
            result = { status: 'denied' }
        } else {
            const idToken = params.id_token
            if (typeof idToken !== 'string' || idToken === '') throw new AuthError('missing_id_token', 'id_token required', 400)
            // §9: 検証。nonce は state から導出した値と比べる。失敗したらログインさせない
            try {
                const claims = verifyIdToken(idToken, {
                    origin: this.origin,
                    nonce: this.nonceFor(challenge),
                    now: this.now(),
                    clockSkew: this.clockSkew
                })
                result = { status: 'ok', claims }
            } catch (e) {
                throw new AuthError('invalid_id_token', `invalid id_token: ${(e as Error).message}`, 400)
            }
        }

        // §9 手順 3: nonce (= この C) を使用済みにする。C の exp を過ぎれば readChallenge が弾くので、記録もそこまででよい。
        // ストアが setIfAbsent を持つなら、検証を通った同時応答のうち 1 件だけが通る
        if (!(await this.markUsed(usedKey, this.ttlUntil(payload.exp)))) {
            throw new AuthError('request_used', 'this request has already been answered', 400)
        }
        return { payload, result }
    }

    private async markUsed(usedKey: string, ttl: number): Promise<boolean> {
        if (this.store.setIfAbsent) return this.store.setIfAbsent(usedKey, '1', ttl)
        await this.store.set(usedKey, '1', ttl)
        return true
    }

    /** nonce (§5.3) は保存せず、チャレンジから秘密鍵で導出する。QR を見た第三者が知ってよい値 (§8.1) */
    private nonceFor(challenge: string): string {
        return derive('nonce', challenge, this.secret)
    }

    private readChallenge(challenge: string, status: number): ChallengePayload {
        try {
            return unpackChallenge(challenge, this.secret, this.now())
        } catch (e) {
            throw new AuthError('invalid_request', `unknown or expired request: ${(e as Error).message}`, status)
        }
    }

    private ttlUntil(exp: number): number {
        return Math.max(1, exp - this.now())
    }
}

/**
 * §5.2: request_uri (https://<host>/<path>) を Authorization Request URI concrnt-auth://<response_mode>/<host>/<path> にする。
 * 応答方式を選ぶのはブラウザ (RP フロント) なので、ブラウザ側でも使える純関数にしてある:
 *   同一端末のアプリを開くリンクには 'fragment'、別端末に読ませる QR には 'direct_post'
 */
export const authorizationRequestUri = (requestUri: string, mode: ResponseMode): string => {
    if (!RESPONSE_MODES.includes(mode)) throw new AuthError('invalid_option', `unknown response_mode: ${mode}`, 500)
    const prefix = 'https://'
    if (!requestUri.startsWith(prefix)) throw new AuthError('invalid_option', `request_uri must be https: ${requestUri}`, 500)
    return `concrnt-auth://${mode}/${requestUri.slice(prefix.length)}`
}

/**
 * §8.1 (form) / §8.2 (フラグメント) の応答パラメータを取り出す。
 * `new URLSearchParams(location.hash.slice(1))` や `await request.formData()` をそのまま渡せる。未知のパラメータは無視する
 */
export const parseAuthorizationResponse = (source: FormData | URLSearchParams): AuthorizationResponseParams => {
    const pick = (name: string): string | null => {
        const value = source.get(name)
        return typeof value === 'string' ? value : null
    }
    return { id_token: pick('id_token'), error: pick('error') }
}

// display_code は session のハッシュから作る。同じチャレンジなら QR でもリンクでも同じ絵文字
const displayCodeFor = (sh: Uint8Array): string => emojihash(base64urlEncode(sh))

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
