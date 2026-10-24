// Sign-In with Concrnt (CIP-17) を better-auth のプラグインにしたもの。
//
// 設計の要点:
//   - Concrnt の ID Token は「外部で署名された ID Token」なので、better-auth が OAuth / One Tap で使っている
//     handleOAuthUserInfo にそのまま渡す。account 行 (providerId 'concrnt', accountId = CCID) があればサインイン、
//     無ければサインアップ (signUp: 'confirm' なら確認を挟む、'disabled' なら拒否)。専用テーブルは持たない
//   - ceremony は 1 種類 (ログインだけ)。1 ユーザーに CCID は 1 つで、既存ユーザーへの CCID の追加は提供しない
//   - 状態は better-auth の verification テーブルの行だけ。要求ごとに 1 行 (`concrnt-auth:request:<C>`) を置き、
//     受理時に原子的に消費する (= CIP-17 §9 手順 3 の nonce 一回限り)。別端末フローの結果は
//     `concrnt-auth:result:<H(pollToken)>` に置き、開始したブラウザが pollToken で原子的に取り出す
//   - プロトコルの純粋な部分 (ID Token の検証、Authorization Request URI、display_code) だけを @concrnt/auth-client から使う
//
//   ブラウザ                              better-auth (basePath 配下)                        Authenticator (world-app)
//   --------                              ---------------------------                        -------------------------
//   POST /concrnt/start {callbackURL?, newUserCallbackURL?}  要求の行を作る。両方の Authorization Request URI と pollToken を返す
//   QR (direct_post) / リンク (fragment) に
//                                         GET  /concrnt/request/:C          <----------------- Request Object を取りに来る
//   --- 別端末 (direct_post, §8.1) ---
//                                         POST /concrnt/callback/:C         <----------------- 検証し、要求の行を消費して結果を預ける。204 (送信者には何も発行しない)
//   POST /concrnt/status {pollToken} ----> 結果を取り出し、このブラウザのためにサインイン/紐付けしてセッションを発行
//   --- 同一端末 (fragment, §8.2) ---
//   /concrnt/callback/:C#id_token=… -----> GET は着地ページ (HTML) を返す
//   POST /concrnt/exchange/:C -----------> 検証し、要求の行を消費して、このブラウザのためにサインイン/紐付け
//   --- 未登録の CCID で signUp: 'confirm' のとき ---
//   (status / exchange が) ユーザーを作らず、検証済みの内容を保留行に置き、その id を署名付き cookie に入れて
//                                         { status: 'signup_required', profile } を返す
//   GET  /concrnt/pending-sign-up -------> cookie の保留行から profile を返す (確認画面用)
//   POST /concrnt/sign-up ---------------> 保留行を消費してユーザーを作り、セッションを発行する。断るなら何も呼ばない
// 型は better-auth のルートから取る (better-call 由来の endpoint 型を宣言ファイルで名付けられるようにするため)
import type { BetterAuthPlugin, GenericEndpointContext } from 'better-auth'
import { createAuthEndpoint } from '@better-auth/core/api'
import { createPlaceholderEmail } from '@better-auth/core/utils/email'
import { APIError } from 'better-auth/api'
import { setSessionCookie } from 'better-auth/cookies'
import { parseUserOutput } from 'better-auth/db'
import { handleOAuthUserInfo } from 'better-auth/oauth2'
import * as z from 'zod'
import { authorizationRequestUri, emojihash, verifyIdToken, type ClientMetadata, type IdTokenClaims, type RequestObject } from '@concrnt/auth-client'
import { CONCRNT_ERROR_CODES } from './error-codes.js'
import { DEFAULT_LANDING_TEXTS, landingScriptHash, renderLanding, type LandingTexts } from './landing.js'

export { CONCRNT_ERROR_CODES } from './error-codes.js'
export type { LandingTexts } from './landing.js'

/** account.providerId */
export const CONCRNT_PROVIDER_ID = 'concrnt'

export interface ConcrntPluginOptions {
    /** §5.3 client_metadata。同意画面に表示される。既定は `{ client_name: appName }` */
    clientMetadata?: ClientMetadata | undefined
    /**
     * 未登録の CCID でログインされたときの扱い。既定 'auto'
     * - 'auto': その場でユーザーを作ってログインする
     * - 'confirm': ユーザーを作らず `{ status: 'signup_required', profile }` を返す。ブラウザが確認を取り、
     *   POST /concrnt/sign-up で作る (再承認は不要。保留は 10 分で失効する)
     * - 'disabled': SIGNUP_DISABLED (403)。登録済みの CCID だけがログインできる
     */
    signUp?: 'auto' | 'confirm' | 'disabled' | undefined
    /** Request Object の有効期間 (秒)。既定 300 */
    requestTtl?: number | undefined
    /** fragment 着地ページ (GET /concrnt/callback/:C) の文言 */
    landing?: Partial<LandingTexts> | undefined
}

const REQUEST_PREFIX = 'concrnt-auth:request:'
const RESULT_PREFIX = 'concrnt-auth:result:'
const SIGNUP_PREFIX = 'concrnt-auth:signup:'
/** 別端末フローの結果を、要求の失効後も回収できる猶予 (秒) */
const RESULT_GRACE = 60
/** signUp: 'confirm' の保留の有効期間 (秒) */
const SIGNUP_TTL = 600
/** 保留中のサインアップの id を入れる cookie (better-auth の prefix と属性が付く) */
const SIGNUP_COOKIE = 'concrnt_signup'

/** 要求ごとの行 (`concrnt-auth:request:<C>`)。受理時に消費される */
interface PendingRequest {
    nonce: string
    exp: number
    callbackURL: string
    /** 新規ユーザーが作られたときの戻り先 (OAuth の newUserCallbackURL と同じ)。無ければ callbackURL */
    newUserCallbackURL?: string | undefined
    /** 開始したブラウザの秘密 pollToken の SHA-256 (base64url)。別端末フローの結果の宛先 */
    pollHash: string
}

/** 受理した応答 (`concrnt-auth:result:<pollHash>` に置くもの、または exchange でその場で使うもの) */
interface Outcome {
    request: PendingRequest
    /** 拒否応答 (§8.3) のときは無い */
    idToken?: string | undefined
    claims?: IdTokenClaims | undefined
}

export const concrnt = (options: ConcrntPluginOptions = {}) => {
    const requestTtl = options.requestTtl ?? 300
    const signUp = options.signUp ?? 'auto'
    const landingTexts: LandingTexts = { ...DEFAULT_LANDING_TEXTS, ...options.landing }

    // --- URL ---

    const originOf = (ctx: GenericEndpointContext): string => new URL(ctx.context.baseURL).origin
    const pathOf = (ctx: GenericEndpointContext, suffix: string): string => `${ctx.context.baseURL.replace(/\/$/, '')}/concrnt/${suffix}`

    // --- 要求の行 ---

    const findRequest = async (ctx: GenericEndpointContext, challenge: string): Promise<PendingRequest> => {
        const row = await ctx.context.internalAdapter.findVerificationValue(REQUEST_PREFIX + challenge)
        if (!row || row.expiresAt.getTime() <= Date.now()) throw APIError.from('NOT_FOUND', CONCRNT_ERROR_CODES.CHALLENGE_NOT_FOUND)
        return JSON.parse(row.value) as PendingRequest
    }

    /**
     * §8.1 / §8.2 共通: 届いた URL の C の要求を引き、ID Token を検証 (§9) または拒否応答 (§8.3) を読み、
     * 要求の行を原子的に消費する (§9 手順 3: nonce は一回限り。QR とリンクは同じ要求なので片方で成立すればもう片方も使えない)。
     * 検証に失敗した応答は消費しない
     */
    const accept = async (ctx: GenericEndpointContext, challenge: string, params: { id_token?: string | null | undefined; error?: string | null | undefined }): Promise<Outcome> => {
        const request = await findRequest(ctx, challenge)
        let idToken: string | undefined
        let claims: IdTokenClaims | undefined
        if (params.error !== 'access_denied') {
            if (typeof params.id_token !== 'string' || params.id_token === '') throw APIError.from('BAD_REQUEST', CONCRNT_ERROR_CODES.MISSING_ID_TOKEN)
            idToken = params.id_token
            try {
                claims = verifyIdToken(idToken, { origin: originOf(ctx), nonce: request.nonce })
            } catch (e) {
                throw APIError.from('BAD_REQUEST', { ...CONCRNT_ERROR_CODES.INVALID_ID_TOKEN, message: `Invalid id_token: ${(e as Error).message}` })
            }
        }
        const consumed = await ctx.context.internalAdapter.consumeVerificationValue(REQUEST_PREFIX + challenge)
        if (!consumed) throw APIError.from('BAD_REQUEST', CONCRNT_ERROR_CODES.CHALLENGE_ALREADY_USED)
        return { request, idToken, claims }
    }

    /**
     * 受理済みの応答で、呼び出し元のブラウザのためにサインイン / サインアップを行い、セッションを発行する。
     * 未登録の CCID は signUp に従う ('confirm' ならここでは作らず保留にする)
     */
    const complete = async (ctx: GenericEndpointContext, outcome: Outcome) => {
        const { request, idToken, claims } = outcome
        if (!claims || !idToken) return ctx.json({ status: 'denied' as const, callbackURL: request.callbackURL })
        if (signUp !== 'auto') {
            const existing = await ctx.context.internalAdapter.findAccountByKey({ providerId: CONCRNT_PROVIDER_ID, accountId: claims.sub })
            if (!existing) {
                if (signUp === 'disabled') throw APIError.from('FORBIDDEN', CONCRNT_ERROR_CODES.SIGNUP_DISABLED)
                return holdSignUp(ctx, outcome)
            }
        }
        return signIn(ctx, { ...outcome, idToken, claims })
    }

    /** signUp: 'confirm': 検証済みの内容を保留行に置き、その id を署名付き cookie に入れる。ユーザーはまだ作らない */
    const holdSignUp = async (ctx: GenericEndpointContext, outcome: Outcome) => {
        const id = randomToken(32)
        await ctx.context.internalAdapter.createVerificationValue({
            identifier: SIGNUP_PREFIX + id,
            value: JSON.stringify(outcome),
            expiresAt: new Date(Date.now() + SIGNUP_TTL * 1000)
        })
        const cookie = ctx.context.createAuthCookie(SIGNUP_COOKIE, { maxAge: SIGNUP_TTL })
        await ctx.setSignedCookie(cookie.name, id, ctx.context.secret, cookie.attributes)
        return ctx.json({ status: 'signup_required' as const, callbackURL: outcome.request.callbackURL, profile: profileOf(outcome) })
    }

    /** 保留中のサインアップの行 (cookie から)。無ければ null */
    const findPendingSignUp = async (ctx: GenericEndpointContext): Promise<{ id: string; outcome: Outcome } | null> => {
        const cookie = ctx.context.createAuthCookie(SIGNUP_COOKIE)
        const id = await ctx.getSignedCookie(cookie.name, ctx.context.secret)
        if (!id) return null
        const row = await ctx.context.internalAdapter.findVerificationValue(SIGNUP_PREFIX + id)
        if (!row || row.expiresAt.getTime() <= Date.now()) return null
        return { id, outcome: JSON.parse(row.value) as Outcome }
    }

    const clearPendingSignUp = (ctx: GenericEndpointContext): void => {
        const cookie = ctx.context.createAuthCookie(SIGNUP_COOKIE)
        ctx.setCookie(cookie.name, '', { ...cookie.attributes, maxAge: 0 })
    }

    /**
     * サインイン / サインアップを行い、セッションを発行する。
     * 判定は better-auth の handleOAuthUserInfo (OAuth / One Tap と同じもの) に任せる:
     * account 行があればそのユーザー (提示したブラウザが別のユーザーでログイン中でも切り替わる)、無ければ作る
     */
    const signIn = async (ctx: GenericEndpointContext, { request, idToken, claims }: Outcome & { idToken: string; claims: IdTokenClaims }) => {
        const ccid = claims.sub
        const result = await handleOAuthUserInfo(ctx, {
            userInfo: {
                id: ccid,
                // better-auth の user には email が必須。Concrnt にメールは無いので到達不能なプレースホルダーを使う (SIWE と同じ)
                email: createPlaceholderEmail({ identifier: ccid, namespace: CONCRNT_PROVIDER_ID }),
                emailVerified: false,
                // name / picture は Authenticator の自己申告 (CIP-17 §7.3)。表示用途に留める
                name: claims.name ?? ccid,
                image: claims.picture ?? null
            },
            account: { providerId: CONCRNT_PROVIDER_ID, accountId: ccid, idToken, scope: 'openid,profile' },
            callbackURL: request.callbackURL,
            disableSignUp: signUp === 'disabled'
        })
        if (result.error !== null || !result.data) {
            if (result.error === 'signup disabled') throw APIError.from('FORBIDDEN', CONCRNT_ERROR_CODES.SIGNUP_DISABLED)
            throw APIError.from('UNAUTHORIZED', { ...CONCRNT_ERROR_CODES.UNABLE_TO_SIGN_IN, message: result.error || CONCRNT_ERROR_CODES.UNABLE_TO_SIGN_IN.message })
        }
        await setSessionCookie(ctx, result.data)
        const isNewUser = result.isRegister === true
        return ctx.json({
            status: 'ok' as const,
            callbackURL: (isNewUser && request.newUserCallbackURL) || request.callbackURL,
            /** この応答で新しいユーザーが作られた (初めての CCID) */
            isNewUser,
            token: result.data.session.token,
            user: parseUserOutput(ctx.context.options, result.data.user)
        })
    }

    // --- endpoint ---

    const start = createAuthEndpoint(
        '/concrnt/start',
        {
            method: 'POST',
            // callbackURL / newUserCallbackURL は better-auth の origin チェック (全 endpoint 共通) が trustedOrigins で検証する
            body: z
                .object({
                    callbackURL: z.string().max(2048).optional(),
                    newUserCallbackURL: z.string().max(2048).optional()
                })
                .optional(),
            metadata: {
                noStore: true,
                openapi: {
                    operationId: 'startConcrnt',
                    description:
                        'Start Sign-In with Concrnt (CIP-17). Returns the Authorization Request URIs for QR (direct_post) and link (fragment). A new user is sent to newUserCallbackURL (if given) instead of callbackURL.'
                }
            }
        },
        async (ctx) => {
            // 新しいログインを始めたら、前回の保留中のサインアップ (signUp: 'confirm') は捨てる
            clearPendingSignUp(ctx)
            const challenge = randomToken(16)
            const pollToken = randomToken(32)
            const exp = Math.floor(Date.now() / 1000) + requestTtl
            const request: PendingRequest = {
                nonce: randomToken(32),
                exp,
                callbackURL: ctx.body?.callbackURL ?? '/',
                newUserCallbackURL: ctx.body?.newUserCallbackURL,
                pollHash: await sha256(pollToken)
            }
            await ctx.context.internalAdapter.createVerificationValue({
                identifier: REQUEST_PREFIX + challenge,
                value: JSON.stringify(request),
                expiresAt: new Date(exp * 1000)
            })
            const requestUri = pathOf(ctx, `request/${challenge}`)
            return ctx.json({
                // 応答方式を選ぶのはブラウザ (§8)。QR には direct_post、同一端末で開くリンクには fragment
                directPostUri: authorizationRequestUri(requestUri, 'direct_post'),
                fragmentUri: authorizationRequestUri(requestUri, 'fragment'),
                displayCode: emojihash(challenge),
                exp,
                /** 開始したブラウザだけが知る秘密 (§8.1)。status の回収に使う。QR には載らない */
                pollToken
            })
        }
    )

    const getRequestObject = createAuthEndpoint(
        '/concrnt/request/:challenge',
        {
            method: 'GET',
            metadata: {
                noStore: true,
                openapi: { operationId: 'getConcrntRequestObject', description: 'CIP-17 §5.3 Request Object (fetched by the Authenticator).' }
            }
        },
        async (ctx) => {
            // Authenticator がブラウザ由来の fetch で来る場合 (web 版 Authenticator) に必要
            ctx.setHeader('Access-Control-Allow-Origin', '*')
            const request = await findRequest(ctx, ctx.params.challenge)
            const requestObject: RequestObject = {
                redirect_uri: pathOf(ctx, `callback/${ctx.params.challenge}`),
                response_type: 'id_token',
                scope: 'openid profile',
                nonce: request.nonce,
                exp: request.exp,
                display_code: emojihash(ctx.params.challenge),
                client_metadata: options.clientMetadata ?? { client_name: ctx.context.appName }
            }
            return ctx.json(requestObject)
        }
    )

    const receiveDirectPost = createAuthEndpoint(
        '/concrnt/callback/:challenge',
        {
            method: 'POST',
            body: z.looseObject({ id_token: z.string().optional(), error: z.string().optional() }),
            metadata: {
                // §8.1: Authenticator は application/x-www-form-urlencoded で id_token を POST する
                allowedMediaTypes: ['application/x-www-form-urlencoded', 'application/json'],
                noStore: true,
                openapi: {
                    operationId: 'concrntDirectPost',
                    description:
                        'CIP-17 §8.1 direct_post endpoint (called by the Authenticator). Holds the result for the browser that started the request. Never issues a session to the caller.'
                }
            }
        },
        async (ctx) => {
            ctx.setHeader('Access-Control-Allow-Origin', '*')
            const outcome = await accept(ctx, ctx.params.challenge, ctx.body)
            await ctx.context.internalAdapter.createVerificationValue({
                identifier: RESULT_PREFIX + outcome.request.pollHash,
                value: JSON.stringify(outcome),
                expiresAt: new Date((outcome.request.exp + RESULT_GRACE) * 1000)
            })
            return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*' } })
        }
    )

    const landing = createAuthEndpoint(
        '/concrnt/callback/:challenge',
        {
            method: 'GET',
            metadata: {
                noStore: true,
                openapi: { operationId: 'concrntFragmentLanding', description: 'CIP-17 §8.2 fragment landing page. Forwards #id_token to the exchange endpoint.' }
            }
        },
        async () =>
            new Response(renderLanding(landingTexts), {
                status: 200,
                headers: {
                    'Content-Type': 'text/html; charset=utf-8',
                    'Cache-Control': 'no-store',
                    'Referrer-Policy': 'no-referrer',
                    'Content-Security-Policy': `default-src 'none'; script-src ${await landingScriptHash()}; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'`
                }
            })
    )

    const exchange = createAuthEndpoint(
        '/concrnt/exchange/:challenge',
        {
            method: 'POST',
            body: z.object({ id_token: z.string().nullish(), error: z.string().nullish() }),
            requireHeaders: true,
            metadata: {
                noStore: true,
                openapi: {
                    operationId: 'concrntExchange',
                    description: 'CIP-17 §8.2: the browser that opened redirect_uri#id_token=… presents the fragment. Issues a session to this browser.'
                }
            }
        },
        async (ctx) => complete(ctx, await accept(ctx, ctx.params.challenge, ctx.body))
    )

    const status = createAuthEndpoint(
        '/concrnt/status',
        {
            // POST + JSON: GET だと cross-site のトップレベル遷移でセッションが発行できてしまう (login CSRF)
            method: 'POST',
            body: z.object({ pollToken: z.string().min(1) }),
            requireHeaders: true,
            metadata: {
                noStore: true,
                openapi: {
                    operationId: 'concrntStatus',
                    description: 'CIP-17 §8.1: the browser that started the request polls for the direct_post result with its pollToken. Issues a session to this browser when the result is ok.'
                }
            }
        },
        async (ctx) => {
            const row = await ctx.context.internalAdapter.consumeVerificationValue(RESULT_PREFIX + (await sha256(ctx.body.pollToken)))
            if (!row) return ctx.json({ status: 'pending' as const })
            return complete(ctx, JSON.parse(row.value) as Outcome)
        }
    )

    const pendingSignUp = createAuthEndpoint(
        '/concrnt/pending-sign-up',
        {
            method: 'GET',
            requireHeaders: true,
            metadata: {
                noStore: true,
                openapi: {
                    operationId: 'getConcrntPendingSignUp',
                    description: "signUp: 'confirm': the verified but not yet created identity held for this browser, or null."
                }
            }
        },
        async (ctx) => {
            const pending = await findPendingSignUp(ctx)
            return ctx.json({ profile: pending ? profileOf(pending.outcome) : null })
        }
    )

    const confirmSignUp = createAuthEndpoint(
        '/concrnt/sign-up',
        {
            method: 'POST',
            requireHeaders: true,
            metadata: {
                noStore: true,
                openapi: {
                    operationId: 'concrntSignUp',
                    description: "signUp: 'confirm': create the user for the identity held for this browser and issue a session. One-shot."
                }
            }
        },
        async (ctx) => {
            const pending = await findPendingSignUp(ctx)
            const row = pending ? await ctx.context.internalAdapter.consumeVerificationValue(SIGNUP_PREFIX + pending.id) : null
            if (!row) throw APIError.from('BAD_REQUEST', CONCRNT_ERROR_CODES.NO_PENDING_SIGNUP)
            clearPendingSignUp(ctx)
            const outcome = JSON.parse(row.value) as Outcome
            if (!outcome.claims || !outcome.idToken) throw APIError.from('BAD_REQUEST', CONCRNT_ERROR_CODES.NO_PENDING_SIGNUP)
            return signIn(ctx, { ...outcome, claims: outcome.claims, idToken: outcome.idToken })
        }
    )

    return {
        id: 'concrnt',
        endpoints: {
            startConcrnt: start,
            getConcrntRequestObject: getRequestObject,
            concrntDirectPost: receiveDirectPost,
            concrntFragmentLanding: landing,
            concrntExchange: exchange,
            concrntStatus: status,
            getConcrntPendingSignUp: pendingSignUp,
            concrntSignUp: confirmSignUp
        },
        rateLimit: [
            { pathMatcher: (path) => path === '/concrnt/start', window: 60, max: 30 },
            { pathMatcher: (path) => path === '/concrnt/status', window: 60, max: 120 },
            { pathMatcher: (path) => path === '/concrnt/sign-up', window: 60, max: 30 }
        ],
        $ERROR_CODES: CONCRNT_ERROR_CODES,
        options
    } satisfies BetterAuthPlugin
}

export type ConcrntPlugin = ReturnType<typeof concrnt>

/** 確認画面に出す、検証済みだがまだユーザーになっていない identity。name / picture は Authenticator の自己申告 */
export interface PendingProfile {
    ccid: string
    name: string | null
    picture: string | null
}

const profileOf = ({ claims }: Outcome): PendingProfile => ({ ccid: claims!.sub, name: claims!.name ?? null, picture: claims!.picture ?? null })

const randomToken = (bytes: number): string => base64url(crypto.getRandomValues(new Uint8Array(bytes)))

const sha256 = async (value: string): Promise<string> => base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))))

const base64url = (bytes: Uint8Array): string => {
    let binary = ''
    for (const byte of bytes) binary += String.fromCharCode(byte)
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
