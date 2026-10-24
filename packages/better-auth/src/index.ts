// Sign-In with Concrnt (CIP-17) を better-auth のプラグインにしたもの。プロトコル処理は @concrnt/auth-client に任せ、
// ここでは better-auth の endpoint・ユーザー/セッション・verification テーブルに結び付ける。
//
// 形はパスキープラグイン (@better-auth/passkey) に揃えてある:
//   専用テーブル concrntIdentity (1 ユーザーに複数の CCID) / registration と authentication の 2 つの ceremony /
//   registration.requireSession・resolveUser・afterVerification / 一覧・削除・更新
//
//   ブラウザ                              better-auth (basePath 配下)                       Authenticator (world-app)
//   --------                              ---------------------------                       -------------------------
//   POST /concrnt/start-authentication    auth.start() + ceremony 行を verification に保存
//   POST /concrnt/start-registration      (同上。セッションのユーザーを ceremony に記録)
//   requestUri を QR (direct_post) / リンク (fragment) に
//                                         GET  /concrnt/request/:C         <----------------- Request Object を取りに来る
//   --- 別端末 (direct_post) ---
//                                         POST /concrnt/callback/:C        <----------------- id_token を預ける (送信者には何も発行しない)
//   GET  /concrnt/status?pollToken= -----> 結果を回収し、このブラウザのために ceremony を完了 (セッション発行)
//   --- 同一端末 (fragment) ---
//   /concrnt/callback/:C#id_token=… -----> GET は着地ページ (HTML) を返す
//   POST /concrnt/exchange/:C -----------> 検証し、このブラウザのために ceremony を完了
//
// 状態は verification テーブルだけ: メールボックスと使用済み記録 (@concrnt/auth-client の AuthStore として) と、
// 要求ごとの ceremony 行 `concrnt-auth:ceremony:<requestId>` (種別・開始したユーザー・callbackURL)
import type { BetterAuthPlugin, GenericEndpointContext } from '@better-auth/core'
import type { Session, User } from '@better-auth/core/db'
import type { InferOptionSchema } from 'better-auth'
import { createAuthEndpoint } from '@better-auth/core/api'
import { getCurrentAdapter, runWithTransaction } from '@better-auth/core/context'
import {
    APIError,
    freshSessionMiddleware,
    getSessionFromCtx,
    originCheck,
    requireResourceOwnership,
    sessionMiddleware
} from 'better-auth/api'
import { setSessionCookie } from 'better-auth/cookies'
import { mergeSchema } from 'better-auth/db'
import * as z from 'zod'
import {
    AuthError,
    ConcrntAuth,
    authorizationRequestUri,
    type ClientMetadata,
    type IdTokenClaims,
    type LoginResult,
    type StartedLogin
} from '@concrnt/auth-client'
import { CONCRNT_ERROR_CODES } from './error-codes.js'
import { DEFAULT_LANDING_TEXTS, landingScriptHash, renderLanding, type LandingTexts } from './landing.js'
import { schema, type ConcrntIdentity } from './schema.js'
import { verificationStore } from './store.js'

export { CONCRNT_ERROR_CODES } from './error-codes.js'
export { schema as concrntSchema, type ConcrntIdentity } from './schema.js'
export type { LandingTexts } from './landing.js'

type Awaitable<T> = T | Promise<T>

export interface ConcrntRegistrationUser {
    id: string
    name?: string | undefined
}

export interface ConcrntRegistrationOptions {
    /**
     * 登録 (CCID の追加) にログイン済みセッションを要求する。
     * false にすると未ログインでも開始でき、受理時に resolveUser / afterVerification が決めたユーザーに紐付ける
     * @default true
     */
    requireSession?: boolean | undefined
    /**
     * requireSession が false でセッションも無いときに、開始時点で登録先ユーザーを決める。
     * 省略すると受理時の afterVerification が userId を返すことを要求する (CCID とプロフィールを見てからユーザーを作れる)
     */
    resolveUser?: ((args: { ctx: GenericEndpointContext; context?: string | null | undefined }) => Awaitable<ConcrntRegistrationUser>) | undefined
    /**
     * ID Token の検証に成功した後、identity を保存する前に呼ばれる。
     * `userId` を返すと登録先を差し替える (開始時にユーザーが決まっていなければ必須)。`name` はクライアントが
     * ラベルを指定しなかったときの既定値になる
     */
    afterVerification?:
        | ((args: {
              ctx: GenericEndpointContext
              claims: IdTokenClaims
              user: ConcrntRegistrationUser | undefined
              context?: string | null | undefined
          }) => Awaitable<{ userId?: string | undefined; name?: string | undefined } | void>)
        | undefined
}

export interface ConcrntAuthenticationOptions {
    /** ID Token の検証と identity の照合に成功した後、セッションを作る前に呼ばれる */
    afterVerification?: ((args: { ctx: GenericEndpointContext; claims: IdTokenClaims; identity: ConcrntIdentity }) => Awaitable<void>) | undefined
}

export interface ConcrntPluginOptions {
    /**
     * RP のオリジン (CIP-17 §5.1)。request_uri / redirect_uri のオリジンで、ID Token の aud になる。
     * 既定は better-auth の baseURL のオリジン。Authorization Request URI には host しか載らず https が暗黙
     */
    origin?: string | undefined
    /** §5.3 client_metadata。既定は `{ client_name: appName }` */
    clientMetadata?: ClientMetadata | undefined
    /** Request Object の有効期間 (秒)。既定 300 */
    requestTtl?: number | undefined
    /** ID Token の iat 判定の許容幅 (秒)。既定 300 */
    clockSkew?: number | undefined
    registration?: ConcrntRegistrationOptions | undefined
    authentication?: ConcrntAuthenticationOptions | undefined
    /** fragment 着地ページ (GET /concrnt/callback/:C) の文言 */
    landing?: Partial<LandingTexts> | undefined
    schema?: InferOptionSchema<typeof schema> | undefined
}

const CEREMONY_PREFIX = 'concrnt-auth:ceremony:'
const MODEL = 'concrntIdentity'

interface Ceremony {
    type: 'authentication' | 'registration'
    callbackURL: string
    /** registration: 開始時に決まった登録先 */
    userId?: string | undefined
    userName?: string | undefined
    /** registration: クライアントが付けたラベル */
    name?: string | undefined
    context?: string | null | undefined
    createSession?: boolean | undefined
}

const callbackURLSchema = z.string().max(2048).optional()

export const concrnt = (options: ConcrntPluginOptions = {}) => {
    const requireSession = options.registration?.requireSession ?? true
    const landingTexts: LandingTexts = { ...DEFAULT_LANDING_TEXTS, ...options.landing }

    // --- ヘルパー ---

    const buildAuth = (ctx: GenericEndpointContext): ConcrntAuth => {
        // baseURL は basePath を含む (https://rp.example/api/auth)。request_uri / redirect_uri はその配下に置く
        const base = new URL(ctx.context.baseURL)
        const basePath = base.pathname.replace(/\/$/, '')
        try {
            return new ConcrntAuth({
                origin: options.origin ?? base.origin,
                secret: ctx.context.secret,
                store: verificationStore(ctx.context.internalAdapter),
                requestPath: `${basePath}/concrnt/request`,
                redirectPath: `${basePath}/concrnt/callback`,
                clientMetadata: options.clientMetadata ?? { client_name: ctx.context.appName },
                ...(options.requestTtl !== undefined ? { requestTtl: options.requestTtl } : {}),
                ...(options.clockSkew !== undefined ? { clockSkew: options.clockSkew } : {})
            })
        } catch (e) {
            throw toAPIError(e)
        }
    }

    const saveCeremony = async (ctx: GenericEndpointContext, started: StartedLogin, ceremony: Ceremony): Promise<void> => {
        await ctx.context.internalAdapter.createVerificationValue({
            identifier: CEREMONY_PREFIX + started.requestId,
            value: JSON.stringify(ceremony),
            expiresAt: new Date(started.exp * 1000)
        })
    }

    const takeCeremony = async (ctx: GenericEndpointContext, requestId: string): Promise<Ceremony> => {
        const record = await ctx.context.internalAdapter.consumeVerificationValue(CEREMONY_PREFIX + requestId)
        if (!record) throw APIError.fromStatus('BAD_REQUEST', CONCRNT_ERROR_CODES.CEREMONY_NOT_FOUND)
        return JSON.parse(record.value) as Ceremony
    }

    const startResponse = (started: StartedLogin) => ({
        requestUri: started.requestUri,
        // 応答方式を選ぶのはブラウザ (§8)。QR には direct_post、同一端末で開くリンクには fragment
        directPostUri: authorizationRequestUri(started.requestUri, 'direct_post'),
        fragmentUri: authorizationRequestUri(started.requestUri, 'fragment'),
        displayCode: started.displayCode,
        exp: started.exp,
        /** 開始したブラウザだけが知る秘密 (§8.1)。status の回収に使う。QR には載らない */
        pollToken: started.session
    })

    const findIdentity = async (ctx: GenericEndpointContext, ccid: string): Promise<ConcrntIdentity | null> =>
        ctx.context.adapter.findOne<ConcrntIdentity>({ model: MODEL, where: [{ field: 'ccid', value: ccid }] })

    /**
     * 検証済みの結果で ceremony を完了し、呼び出し元のブラウザにセッションを発行する。
     * route は結果が届いた経路: 'status' = 開始したブラウザ (pollToken 保持者)、'exchange' = フラグメントを提示したブラウザ (§8.2)
     */
    const complete = async (ctx: GenericEndpointContext, requestId: string, result: LoginResult, route: 'status' | 'exchange') => {
        const ceremony = await takeCeremony(ctx, requestId)
        if (result.status === 'denied') return ctx.json({ status: 'denied' as const, callbackURL: ceremony.callbackURL })
        const { claims } = result

        if (ceremony.type === 'authentication') {
            const identity = await findIdentity(ctx, claims.sub)
            if (!identity) throw APIError.fromStatus('UNAUTHORIZED', CONCRNT_ERROR_CODES.IDENTITY_NOT_FOUND)
            await options.authentication?.afterVerification?.({ ctx, claims, identity })
            await ctx.context.adapter.update({
                model: MODEL,
                where: [{ field: 'id', value: identity.id }],
                update: { domain: claims.concrnt_domain, updatedAt: new Date() }
            })
            const user = await ctx.context.internalAdapter.findUserById(identity.userId)
            if (!user) throw APIError.fromStatus('INTERNAL_SERVER_ERROR', CONCRNT_ERROR_CODES.USER_NOT_FOUND)
            const session = await ctx.context.internalAdapter.createSession(identity.userId)
            if (!session) throw APIError.fromStatus('INTERNAL_SERVER_ERROR', CONCRNT_ERROR_CODES.UNABLE_TO_CREATE_SESSION)
            await setSessionCookie(ctx, { session, user })
            return ctx.json({ status: 'ok' as const, callbackURL: ceremony.callbackURL, user, session, identity })
        }

        // registration
        const current = await getSessionFromCtx(ctx)
        if (ceremony.userId) {
            // 開始時に決まったユーザーと、いま結果を持ってきたブラウザのユーザーが違えば拒否 (パスキーと同じ照合)。
            // fragment (§8.2) では提示したブラウザがそのユーザーでログインしていることまで要求する:
            // 開始したセッションに結果を結び付けてはならず、他人が踏んだリンクで登録が成立してはならない
            if (current && current.user.id !== ceremony.userId) {
                throw APIError.fromStatus('UNAUTHORIZED', CONCRNT_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_IDENTITY)
            }
            if (route === 'exchange' && !current) throw APIError.fromStatus('UNAUTHORIZED', CONCRNT_ERROR_CODES.SESSION_REQUIRED)
        }
        // 既に登録済みの CCID なら、ユーザーを作る可能性のある afterVerification を呼ぶ前に止める
        if (await findIdentity(ctx, claims.sub)) throw APIError.fromStatus('BAD_REQUEST', CONCRNT_ERROR_CODES.IDENTITY_ALREADY_REGISTERED)
        const startedUser: ConcrntRegistrationUser | undefined = ceremony.userId ? { id: ceremony.userId, name: ceremony.userName } : undefined
        let targetUserId = ceremony.userId
        let name = ceremony.name
        const hook = await options.registration?.afterVerification?.({ ctx, claims, user: startedUser, context: ceremony.context })
        if (hook?.userId) {
            if (typeof hook.userId !== 'string') throw APIError.fromStatus('BAD_REQUEST', CONCRNT_ERROR_CODES.RESOLVED_USER_INVALID)
            if (current && hook.userId !== current.user.id) {
                throw APIError.fromStatus('UNAUTHORIZED', CONCRNT_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_IDENTITY)
            }
            targetUserId = hook.userId
        }
        if (!name) name = hook?.name?.trim() || undefined
        if (!targetUserId) throw APIError.fromStatus('BAD_REQUEST', CONCRNT_ERROR_CODES.RESOLVED_USER_INVALID)
        const userId = targetUserId

        const persist = async (): Promise<{ identity: ConcrntIdentity; session?: Session; user?: User }> => {
            const user = ceremony.createSession ? await ctx.context.internalAdapter.findUserById(userId) : null
            if (ceremony.createSession && !user) throw APIError.fromStatus('INTERNAL_SERVER_ERROR', CONCRNT_ERROR_CODES.USER_NOT_FOUND)
            const now = new Date()
            const identity = await (await getCurrentAdapter(ctx.context.adapter)).create<ConcrntIdentity>({
                model: MODEL,
                data: { userId, ccid: claims.sub, domain: claims.concrnt_domain, name, createdAt: now, updatedAt: now } as unknown as ConcrntIdentity
            })
            if (!user) return { identity }
            const session = await ctx.context.internalAdapter.createSession(userId, undefined, undefined, undefined, {
                deferSecondaryStorageWrites: true
            })
            if (!session) throw APIError.fromStatus('INTERNAL_SERVER_ERROR', CONCRNT_ERROR_CODES.UNABLE_TO_CREATE_SESSION)
            return { identity, session, user }
        }
        const registered = ceremony.createSession ? await runWithTransaction(ctx.context.adapter, persist) : await persist()
        if (registered.session && registered.user) await setSessionCookie(ctx, { session: registered.session, user: registered.user })
        return ctx.json({
            status: 'ok' as const,
            callbackURL: ceremony.callbackURL,
            identity: registered.identity,
            session: registered.session ?? null,
            user: registered.user ?? null
        })
    }

    // --- endpoint ---

    const startAuthentication = createAuthEndpoint(
        '/concrnt/start-authentication',
        {
            method: 'POST',
            body: z.object({ callbackURL: callbackURLSchema }).optional(),
            use: [originCheck((ctx) => ctx.body?.callbackURL ?? '/')],
            metadata: {
                noStore: true,
                openapi: {
                    operationId: 'startConcrntAuthentication',
                    description: 'Start Sign-In with Concrnt (CIP-17). Returns the Authorization Request URIs for QR (direct_post) and link (fragment).'
                }
            }
        },
        async (ctx) => {
            const auth = buildAuth(ctx)
            const started = auth.start()
            await saveCeremony(ctx, started, { type: 'authentication', callbackURL: ctx.body?.callbackURL ?? '/' })
            return ctx.json(startResponse(started))
        }
    )

    const startRegistration = createAuthEndpoint(
        '/concrnt/start-registration',
        {
            method: 'POST',
            body: z
                .object({
                    callbackURL: callbackURLSchema,
                    name: z.string().max(200).optional(),
                    context: z.string().max(2048).optional(),
                    createSession: z.boolean().optional()
                })
                .optional(),
            use: [...(requireSession ? [freshSessionMiddleware] : []), originCheck((ctx) => ctx.body?.callbackURL ?? '/')],
            metadata: {
                noStore: true,
                openapi: {
                    operationId: 'startConcrntRegistration',
                    description: 'Start linking a Concrnt identity (CCID) to a user (CIP-17). Same response shape as start-authentication.'
                }
            }
        },
        async (ctx) => {
            // パスキーの resolveRegistrationUser と同じ順: セッション → resolveUser → (省略なら) 受理時の afterVerification に委ねる
            let user: ConcrntRegistrationUser | undefined
            const session = requireSession ? ctx.context.session : await getSessionFromCtx(ctx)
            if (session?.user?.id) {
                user = { id: session.user.id, name: session.user.email || session.user.id }
            } else if (requireSession) {
                throw APIError.fromStatus('UNAUTHORIZED', CONCRNT_ERROR_CODES.SESSION_REQUIRED)
            } else if (options.registration?.resolveUser) {
                const resolved = await options.registration.resolveUser({ ctx, context: ctx.body?.context ?? null })
                if (!resolved?.id) throw APIError.fromStatus('BAD_REQUEST', CONCRNT_ERROR_CODES.RESOLVED_USER_INVALID)
                user = resolved
            }
            const auth = buildAuth(ctx)
            const started = auth.start()
            await saveCeremony(ctx, started, {
                type: 'registration',
                callbackURL: ctx.body?.callbackURL ?? '/',
                userId: user?.id,
                userName: user?.name,
                name: ctx.body?.name?.trim() || undefined,
                context: ctx.body?.context ?? null,
                createSession: ctx.body?.createSession ?? false
            })
            return ctx.json(startResponse(started))
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
            try {
                return ctx.json(buildAuth(ctx).getRequestObject(ctx.params.challenge))
            } catch (e) {
                throw toAPIError(e)
            }
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
                    description: 'CIP-17 §8.1 direct_post endpoint (called by the Authenticator). Holds the result for the browser that started the request. Never issues a session to the caller.'
                }
            }
        },
        async (ctx) => {
            try {
                await buildAuth(ctx).receiveDirectPost(ctx.params.challenge, { id_token: ctx.body.id_token, error: ctx.body.error })
            } catch (e) {
                throw toAPIError(e)
            }
            return new Response(null, { status: 204 })
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
        async (ctx) => {
            const auth = buildAuth(ctx)
            let result: LoginResult
            try {
                result = await auth.exchange(ctx.params.challenge, { id_token: ctx.body.id_token, error: ctx.body.error })
            } catch (e) {
                throw toAPIError(e)
            }
            return complete(ctx, auth.requestIdOf(ctx.params.challenge), result, 'exchange')
        }
    )

    const status = createAuthEndpoint(
        '/concrnt/status',
        {
            method: 'GET',
            query: z.object({ pollToken: z.string().min(1) }),
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
            const auth = buildAuth(ctx)
            const result = await auth.pollResult(ctx.query.pollToken)
            if (!result) return ctx.json({ status: 'pending' as const })
            return complete(ctx, auth.requestIdOfSession(ctx.query.pollToken), result, 'status')
        }
    )

    const listIdentities = createAuthEndpoint(
        '/concrnt/list-identities',
        {
            method: 'GET',
            use: [sessionMiddleware],
            metadata: { openapi: { operationId: 'listConcrntIdentities', description: 'List the Concrnt identities linked to the current user.' } }
        },
        async (ctx) => {
            const identities = await ctx.context.adapter.findMany<ConcrntIdentity>({
                model: MODEL,
                where: [{ field: 'userId', value: ctx.context.session.user.id }],
                sortBy: { field: 'createdAt', direction: 'asc' }
            })
            return ctx.json(identities)
        }
    )

    const ownership = requireResourceOwnership({
        model: MODEL,
        idParam: 'id',
        idSource: 'body',
        notFoundError: CONCRNT_ERROR_CODES.IDENTITY_NOT_FOUND
    })

    const deleteIdentity = createAuthEndpoint(
        '/concrnt/delete-identity',
        {
            method: 'POST',
            body: z.object({ id: z.string() }),
            use: [sessionMiddleware, ownership],
            metadata: { openapi: { operationId: 'deleteConcrntIdentity', description: 'Unlink a Concrnt identity from the current user.' } }
        },
        async (ctx) => {
            await ctx.context.adapter.delete({ model: MODEL, where: [{ field: 'id', value: ctx.body.id }] })
            return ctx.json({ status: true })
        }
    )

    const updateIdentity = createAuthEndpoint(
        '/concrnt/update-identity',
        {
            method: 'POST',
            body: z.object({ id: z.string(), name: z.string().max(200) }),
            use: [sessionMiddleware, ownership],
            metadata: { openapi: { operationId: 'updateConcrntIdentity', description: 'Rename a linked Concrnt identity.' } }
        },
        async (ctx) => {
            const identity = await ctx.context.adapter.update<ConcrntIdentity>({
                model: MODEL,
                where: [{ field: 'id', value: ctx.body.id }],
                update: { name: ctx.body.name, updatedAt: new Date() }
            })
            if (!identity) throw APIError.fromStatus('NOT_FOUND', CONCRNT_ERROR_CODES.IDENTITY_NOT_FOUND)
            return ctx.json({ identity })
        }
    )

    return {
        id: 'concrnt',
        endpoints: {
            startConcrntAuthentication: startAuthentication,
            startConcrntRegistration: startRegistration,
            getConcrntRequestObject: getRequestObject,
            concrntDirectPost: receiveDirectPost,
            concrntFragmentLanding: landing,
            concrntExchange: exchange,
            concrntStatus: status,
            listConcrntIdentities: listIdentities,
            deleteConcrntIdentity: deleteIdentity,
            updateConcrntIdentity: updateIdentity
        },
        schema: mergeSchema(schema, options.schema),
        rateLimit: [
            { pathMatcher: (path) => path.startsWith('/concrnt/start-'), window: 60, max: 30 },
            { pathMatcher: (path) => path === '/concrnt/status', window: 60, max: 120 }
        ],
        $ERROR_CODES: CONCRNT_ERROR_CODES,
        options
    } satisfies BetterAuthPlugin
}

export type ConcrntPlugin = ReturnType<typeof concrnt>

/** @concrnt/auth-client の AuthError を better-auth の APIError に写す。status はそのまま */
const toAPIError = (e: unknown): unknown => {
    if (!(e instanceof AuthError)) return e
    const code = (
        {
            invalid_option: CONCRNT_ERROR_CODES.INVALID_CONFIGURATION,
            invalid_request: CONCRNT_ERROR_CODES.CHALLENGE_NOT_FOUND,
            request_used: CONCRNT_ERROR_CODES.CHALLENGE_ALREADY_USED,
            missing_id_token: CONCRNT_ERROR_CODES.MISSING_ID_TOKEN,
            invalid_id_token: CONCRNT_ERROR_CODES.INVALID_ID_TOKEN
        } as const
    )[e.code]
    const status = ({ 400: 'BAD_REQUEST', 404: 'NOT_FOUND', 500: 'INTERNAL_SERVER_ERROR' } as const)[e.status as 400 | 404 | 500] ?? 'BAD_REQUEST'
    return APIError.fromStatus(status, { code: code.code, message: e.message })
}
