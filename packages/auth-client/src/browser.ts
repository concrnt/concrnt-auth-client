// ブラウザ側の流れ。サーバー側の HTTP の形は決めず、開始とポーリングの fetch は呼び出し側から受け取る。
//   1. start() で要求を発行し、onChallenge に QR 用 / リンク用の URI と display_code を渡す
//   2. 同一端末 (§8.2) は着地ページがサーバー側で済ませる (このブラウザに戻ってきたときには cookie が入っている)
//   3. 別端末 (§8.1) は pollToken で poll() を繰り返し、ok / denied が返るか、exp を過ぎるか、signal で中断されるまで待つ
// このファイルは Web 標準だけに依存するので、サーバー側の依存 (@noble 等) を引かずに import できる

export interface LoginChallenge {
    /** QR にする Authorization Request URI (concrnt-auth://direct_post/…) */
    directPostUri: string
    /** 同一端末で開くリンク (concrnt-auth://fragment/…)。ユーザー操作の直後に location.href で遷移する */
    fragmentUri: string
    /** QR の横に表示する絵文字。Authenticator の同意画面と見比べる (§6) */
    displayCode: string
    /** 要求の失効時刻 (UNIX 秒) */
    exp: number
}

export interface LoginStartResponse extends LoginChallenge {
    /** 開始したブラウザだけが知る秘密。poll に渡す */
    pollToken: string
}

export interface RunLoginOptions<R> {
    /** 要求を発行する (サーバーの start エンドポイントを叩く)。ConcrntAuth.start() の結果をそのまま返す API でよい */
    start: () => Promise<LoginStartResponse>
    /** pollToken で結果を問い合わせる (サーバーの status エンドポイント)。まだなら `{ status: 'pending' }` */
    poll: (pollToken: string) => Promise<{ status: 'pending' } | R>
    /** 要求が発行されたときに呼ばれる。QR と displayCode を描き、必要なら fragmentUri へ遷移する */
    onChallenge?: ((challenge: LoginChallenge) => void) | undefined
    /** ポーリング間隔 (ms)。既定 2000 */
    pollIntervalMs?: number | undefined
    /** 待機を中断する */
    signal?: AbortSignal | undefined
    /** 現在時刻 (UNIX 秒)。テスト用 */
    now?: (() => number) | undefined
}

export type LoginFlowResult<R> = R | { status: 'expired' } | { status: 'aborted' }

/**
 * ログインを開始して結果を待つ。start / poll が throw した例外はそのまま伝わる。
 * 同一端末フローが別タブで完了した場合はここには現れないので、必要なら利用側がセッションを別途確認して signal で中断する
 */
export const runLogin = async <R extends { status: string }>(options: RunLoginOptions<R>): Promise<LoginFlowResult<R>> => {
    const now = options.now ?? (() => Date.now() / 1000)
    const started = await options.start()
    const { directPostUri, fragmentUri, displayCode, exp, pollToken } = started
    options.onChallenge?.({ directPostUri, fragmentUri, displayCode, exp })

    const interval = options.pollIntervalMs ?? 2000
    while (true) {
        if (options.signal?.aborted) return { status: 'aborted' }
        if (now() >= exp) return { status: 'expired' }
        const res = await options.poll(pollToken)
        if (res.status !== 'pending') return res as R
        await sleep(interval, options.signal)
    }
}

const sleep = (ms: number, signal: AbortSignal | undefined): Promise<void> =>
    new Promise((resolve) => {
        const timer = setTimeout(() => {
            signal?.removeEventListener('abort', onAbort)
            resolve()
        }, ms)
        const onAbort = () => {
            clearTimeout(timer)
            resolve()
        }
        signal?.addEventListener('abort', onAbort, { once: true })
    })
