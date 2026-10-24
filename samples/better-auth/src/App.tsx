// CIP-17 RP のブラウザ側 (better-auth 版)。プロトコルの処理は @concrnt/better-auth/client の authClient に任せ、
// ここには画面だけがある。
//
//   ログインボタン → authClient.signIn.concrnt
//     onChallenge で QR (direct_post) と同一端末リンク (fragment) を受け取り、リンクへ遷移しつつ QR を表示する。
//     別端末 (§8.1): アプリが QR を読んで応答 → クライアントが status をポーリング → ok で useSession が更新される
//     同一端末 (§8.2): アプリが redirect_uri#id_token=… を開く → サーバーの着地ページが exchange → callbackURL (/) に戻る
//   初めての CCID: サーバーが自動でユーザーを作る。別端末フローでは結果の isNewUser、同一端末フローでは
//     newUserCallbackURL (/?welcome=1) への戻りで分かるので、「作成しました」の案内を出す
//   ログイン後: useSession の内容、この CCID (listAccounts の concrnt 行)、サインアウト。1 ユーザーに CCID は 1 つ
import { useEffect, useState } from 'react'
import QRCode from 'qrcode'
import { authClient } from './auth-client.js'

type Waiting = { qr: string; fragmentUri: string; displayCode: string; exp: number }
type Notice = { tone: 'info' | 'error'; text: string }

const WELCOME: Notice = { tone: 'info', text: 'Concrnt のアカウントから新しいユーザーを作成しました。次回からは同じ CCID でこのユーザーにログインします' }

export default function App() {
    const { data: session, isPending, isRefetching, refetch } = authClient.useSession()
    const [waiting, setWaiting] = useState<Waiting | null>(null)
    // 着地ページ (同一端末フロー) からの戻り: ?welcome=1 は新規ユーザー、?error= は失敗。初期表示で拾い、URL からは消す
    const [notice, setNotice] = useState<Notice | null>(() => {
        const params = new URLSearchParams(location.search)
        const error = params.get('error')
        const welcome = params.has('welcome')
        if (!error && !welcome) return null
        history.replaceState(null, '', '/')
        if (welcome) return WELCOME
        return { tone: 'error', text: error === 'access_denied' ? 'ログインが拒否されました' : `ログインに失敗しました (${error})` }
    })
    const [abort, setAbort] = useState<AbortController | null>(null)

    // 待機中: 同一端末フローが別タブ/別ブラウザで完了していれば cookie が付いているので、このタブも追従する
    useEffect(() => {
        if (!waiting) return
        const timer = setInterval(() => void refetch(), 3000)
        return () => clearInterval(timer)
    }, [waiting, refetch])
    useEffect(() => {
        // 待機中にセッションが現れたら (別タブで同一端末フローが完了)、待機を打ち切る。中断された login() が待機画面を閉じる
        if (session && waiting) abort?.abort()
    }, [session, waiting, abort])

    const login = async () => {
        setNotice(null)
        const ac = new AbortController()
        setAbort(ac)
        const result = await authClient.signIn.concrnt({
            callbackURL: '/',
            newUserCallbackURL: '/?welcome=1',
            signal: ac.signal,
            // 応答方式を選ぶのはここ: QR は direct_post、同一端末で開くリンクは fragment。同じ要求から両方作られる
            onChallenge: async (c) => {
                // カスタムスキームへの遷移はユーザー操作の直後でないとブラウザに止められる。アプリが無い端末では何も起きない
                location.href = c.fragmentUri
                setWaiting({ qr: await QRCode.toDataURL(c.directPostUri), fragmentUri: c.fragmentUri, displayCode: c.displayCode, exp: c.exp })
            }
        })
        setWaiting(null)
        if (result.error) {
            setNotice({ tone: 'error', text: `${result.error.code ?? ''} ${result.error.message ?? ''}` })
            return
        }
        switch (result.data.status) {
            case 'denied':
                setNotice({ tone: 'error', text: 'アプリで拒否されました' })
                break
            case 'expired':
                setNotice({ tone: 'error', text: 'ログイン要求の有効期限が切れました' })
                break
            case 'ok':
                if (result.data.isNewUser) setNotice(WELCOME)
                break
        }
    }

    // ローディング表示は初回取得だけ。再取得中 (isRefetching) は未ログインでも isPending が立つので、待機画面がチラつかないよう除く
    if (isPending && !isRefetching && !session) return <p>読み込み中...</p>

    if (waiting) {
        return (
            <main>
                <h1>Concrnt アプリで承認してください</h1>
                <p>
                    <small>アプリが開かなかった場合は、別の端末の Concrnt アプリでこの QR コードを読み取ってください</small>
                </p>
                <img src={waiting.qr} alt="Authorization Request QR" width={256} height={256} />
                <p>
                    照合コード
                    <br />
                    <span style={{ fontSize: '2rem' }}>{waiting.displayCode}</span>
                    <br />
                    <small>アプリの同意画面に同じ絵文字が表示されます</small>
                </p>
                <p>
                    <a href={waiting.fragmentUri}>この端末のアプリで開く</a>
                </p>
                <p>応答を待っています...</p>
                <button onClick={() => abort?.abort()}>やめる</button>
            </main>
        )
    }

    if (!session) {
        return (
            <main>
                <h1>Sign-In with Concrnt × better-auth</h1>
                {notice && <p className={notice.tone}>{notice.text}</p>}
                <p>
                    <button onClick={() => void login()}>Concrnt でログイン</button>
                </p>
                <p>
                    <small>初めての CCID はそのままアカウントが作られます</small>
                </p>
            </main>
        )
    }

    return (
        <main>
            <h1>ログインしました</h1>
            {notice && <p className={notice.tone}>{notice.text}</p>}
            {session.user.image && <img src={session.user.image} alt="" width={64} height={64} />}
            <p>{session.user.name}</p>
            <p>
                <small>
                    user id: <code>{session.user.id}</code>
                </small>
            </p>
            <Ccid />
            <p>
                <button onClick={() => authClient.signOut()}>ログアウト</button>
            </p>
        </main>
    )
}

/** このユーザーの CCID。better-auth 組み込みの listAccounts の providerId 'concrnt' の行 (このサンプルでは 1 つだけ) */
function Ccid() {
    const [ccid, setCcid] = useState<string | null>(null)
    useEffect(() => {
        let active = true
        void authClient.listAccounts().then(({ data }) => {
            if (active) setCcid(data?.find((a) => a.providerId === 'concrnt')?.accountId ?? '?')
        })
        return () => {
            active = false
        }
    }, [])
    return (
        <p>
            <small>
                CCID: <code>{ccid ?? '...'}</code>
            </small>
        </p>
    )
}
