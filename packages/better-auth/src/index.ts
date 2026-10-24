// Sign-In with Concrnt (CIP-17) を better-auth のプラグインにしたもの。
//
// 設計の要点:
//   - Concrnt の ID Token は「外部で署名された ID Token」なので、better-auth が OAuth / One Tap で使っている
//     handleOAuthUserInfo にそのまま渡す。account 行 (providerId 'concrnt', accountId = CCID) があればサインイン、
//     無ければサインアップ (disableSignUp で禁止可)、link ceremony なら開始したユーザーへの紐付け。専用テーブルは持たない
//   - ceremony は 1 種類。ログインと紐付けの違いは「開始時にセッションがあり link: true だったか」だけ
//   - 状態は better-auth の verification テーブルの行だけ。要求ごとに 1 行 (`concrnt-auth:request:<C>`) を置き、
//     受理時に原子的に消費する (= CIP-17 §9 手順 3 の nonce 一回限り)。別端末フローの結果は
//     `concrnt-auth:result:<H(pollToken)>` に置き、開始したブラウザが pollToken で原子的に取り出す
//   - プロトコルの純粋な部分 (ID Token の検証、Authorization Request URI、display_code) だけを @concrnt/auth-client から使う
//
//   ブラウザ                              better-auth (basePath 配下)                        Authenticator (world-app)
//   --------                              ---------------------------                        -------------------------
//   POST /concrnt/start {callbackURL?, link?}  要求の行を作る。両方の Authorization Request URI と pollToken を返す
//   QR (direct_post) / リンク (fragment) に
//                                         GET  /concrnt/request/:C          <----------------- Request Object を取りに来る
//   --- 別端末 (direct_post, §8.1) ---
//                                         POST /concrnt/callback/:C         <----------------- 検証し、要求の行を消費して結果を預ける。204 (送信者には何も発行しない)
//   POST /concrnt/status {pollToken} ----> 結果を取り出し、このブラウザのためにサインイン/紐付けしてセッションを発行
//   --- 同一端末 (fragment, §8.2) ---
//   /concrnt/callback/:C#id_token=… -----> GET は着地ページ (HTML) を返す
//   POST /concrnt/exchange/:C -----------> 検証し、要求の行を消費して、このブラウザのためにサインイン/紐付け
// 型は better-auth のルートから取る (better-call 由来の endpoint 型を宣言ファイルで名付けられるようにするため)
import type { BetterAuthPlugin, GenericEndpointContext } from 'better-auth'
import { createAuthEndpoint } from '@better-auth/core/api'
import { createPlaceholderEmail } from '@better-auth/core/utils/email'
import { APIError, getSessionFromCtx } from 'better-auth/api'
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
     * 未登録の CCID でのログインを拒否する (サインアップさせない)。既定 false。
     * true のとき、未登録の CCID は SIGNUP_DISABLED (403)。登録済みユーザーへの追加は link ceremony で行う
     */
    disableSignUp?: boolean | undefined
    /** Request Object の有効期間 (秒)。既定 300 */
    requestTtl?: number | undefined
    /** fragment 着地ページ (GET /concrnt/callback/:C) の文言 */
    landing?: Partial<LandingTexts> | undefined
}

const REQUEST_PREFIX = 'concrnt-auth:request:'
const RESULT_PREFIX = 'concrnt-auth:result:'
/** 別端末フローの結果を、要求の失効後も回収できる猶予 (秒) */
const RESULT_GRACE = 60

/** 要求ごとの行 (`concrnt-auth:request:<C>`)。受理時に消費される */
interface PendingRequest {
    nonce: string
    exp: number
    callbackURL: string
    /** 開始したブラウザの秘密 pollToken の SHA-256 (base64url)。別端末フローの結果の宛先 */
    pollHash: string
    /** link ceremony: 開始したユーザー。完了時にこのユーザーのセッションを要求する */
    linkUserId?: string | undefined
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
     * 受理済みの応答で、呼び出し元のブラウザのためにサインイン / サインアップ / 紐付けを行い、セッションを発行する。
     * 判定は better-auth の handleOAuthUserInfo (OAuth / One Tap と同じもの) に任せる
     */
    const complete = async (ctx: GenericEndpointContext, { request, idToken, claims }: Outcome) => {
        if (!claims || !idToken) return ctx.json({ status: 'denied' as const, callbackURL: request.callbackURL })
        if (request.linkUserId) {
            const current = await getSessionFromCtx(ctx)
            if (!current || current.user.id !== request.linkUserId) throw APIError.from('UNAUTHORIZED', CONCRNT_ERROR_CODES.LINK_SESSION_MISMATCH)
        }
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
            disableSignUp: options.disableSignUp,
            // link ceremony: 開始したユーザーに紐付ける。CCID が別のユーザーのものなら better-auth が CONFLICT を返す
            selectedUser: request.linkUserId ? { userId: request.linkUserId, profile: 'preserve' } : undefined
        })
        if (result.error !== null || !result.data) {
            if (result.error === 'signup disabled') throw APIError.from('FORBIDDEN', CONCRNT_ERROR_CODES.SIGNUP_DISABLED)
            throw APIError.from('UNAUTHORIZED', { ...CONCRNT_ERROR_CODES.UNABLE_TO_SIGN_IN, message: result.error || CONCRNT_ERROR_CODES.UNABLE_TO_SIGN_IN.message })
        }
        await setSessionCookie(ctx, result.data)
        return ctx.json({
            status: 'ok' as const,
            callbackURL: request.callbackURL,
            token: result.data.session.token,
            user: parseUserOutput(ctx.context.options, result.data.user)
        })
    }

    // --- endpoint ---

    const start = createAuthEndpoint(
        '/concrnt/start',
        {
            method: 'POST',
            // callbackURL は better-auth の origin チェック (全 endpoint 共通) が trustedOrigins で検証する
            body: z.object({ callbackURL: z.string().max(2048).optional(), link: z.boolean().optional() }).optional(),
            metadata: {
                noStore: true,
                openapi: {
                    operationId: 'startConcrnt',
                    description:
                        'Start Sign-In with Concrnt (CIP-17). Returns the Authorization Request URIs for QR (direct_post) and link (fragment). With link: true (session required) the verified CCID is linked to the current user instead.'
                }
            }
        },
        async (ctx) => {
            let linkUserId: string | undefined
            if (ctx.body?.link) {
                const session = await getSessionFromCtx(ctx)
                if (!session) throw APIError.from('UNAUTHORIZED', CONCRNT_ERROR_CODES.SESSION_REQUIRED)
                linkUserId = session.user.id
            }
            const challenge = randomToken(16)
            const pollToken = randomToken(32)
            const exp = Math.floor(Date.now() / 1000) + requestTtl
            const request: PendingRequest = {
                nonce: randomToken(32),
                exp,
                callbackURL: ctx.body?.callbackURL ?? '/',
                pollHash: await sha256(pollToken),
                linkUserId
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

    return {
        id: 'concrnt',
        endpoints: {
            startConcrnt: start,
            getConcrntRequestObject: getRequestObject,
            concrntDirectPost: receiveDirectPost,
            concrntFragmentLanding: landing,
            concrntExchange: exchange,
            concrntStatus: status
        },
        rateLimit: [
            { pathMatcher: (path) => path === '/concrnt/start', window: 60, max: 30 },
            { pathMatcher: (path) => path === '/concrnt/status', window: 60, max: 120 }
        ],
        $ERROR_CODES: CONCRNT_ERROR_CODES,
        options
    } satisfies BetterAuthPlugin
}

export type ConcrntPlugin = ReturnType<typeof concrnt>

const randomToken = (bytes: number): string => base64url(crypto.getRandomValues(new Uint8Array(bytes)))

const sha256 = async (value: string): Promise<string> => base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))))

const base64url = (bytes: Uint8Array): string => {
    let binary = ''
    for (const byte of bytes) binary += String.fromCharCode(byte)
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
