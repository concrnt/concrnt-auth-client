// CIP-17 RP のブラウザ側 (better-auth 版)。プロトコルの処理は @concrnt/better-auth/client の authClient に任せ、
// ここには画面だけがある。
//
//   ログイン / 新規登録ボタン → authClient.signIn.concrnt / authClient.concrnt.addIdentity
//     onChallenge で QR (direct_post) と同一端末リンク (fragment) を受け取り、リンクへ遷移しつつ QR を表示する。
//     別端末 (§8.1): アプリが QR を読んで応答 → クライアントが status をポーリング → ok で useSession が更新される
//     同一端末 (§8.2): アプリが redirect_uri#id_token=… を開く → サーバーの着地ページが exchange → callbackURL (/) に戻る
//   ログイン後: useSession の内容、紐付いた CCID の一覧 (useListIdentities)、追加・改名・解除、サインアウト
import { useEffect, useState } from 'react'
import QRCode from 'qrcode'
import { authClient } from './auth-client.js'

type Waiting = { kind: 'register' | 'login' | 'add'; qr: string; fragmentUri: string; displayCode: string; exp: number }
type Notice = { tone: 'info' | 'error'; text: string }

export default function App() {
    const { data: session, isPending, isRefetching, refetch } = authClient.useSession()
    const [waiting, setWaiting] = useState<Waiting | null>(null)
    // 着地ページが ?error= を付けて戻してきた場合は初期表示で拾い、URL からは消す
    const [notice, setNotice] = useState<Notice | null>(() => {
        const error = new URLSearchParams(location.search).get('error')
        if (!error) return null
        history.replaceState(null, '', '/')
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
        // ログイン/新規登録の待機中にセッションが現れたら (別タブで同一端末フローが完了)、待機を打ち切る。
        // 中断された run() が待機画面を閉じる。ログイン中の「別の CCID を追加」はセッションがあるのが前提なので対象外
        if (session && waiting && waiting.kind !== 'add') abort?.abort()
    }, [session, waiting, abort])

    const run = async (kind: Waiting['kind']) => {
        setNotice(null)
        const ac = new AbortController()
        setAbort(ac)
        // 応答方式を選ぶのはここ: QR は direct_post、同一端末で開くリンクは fragment。同じ要求から両方作られる
        const onChallenge = async (c: { directPostUri: string; fragmentUri: string; displayCode: string; exp: number }) => {
            // カスタムスキームへの遷移はユーザー操作の直後でないとブラウザに止められる。アプリが無い端末では何も起きない
            location.href = c.fragmentUri
            setWaiting({ kind, qr: await QRCode.toDataURL(c.directPostUri), fragmentUri: c.fragmentUri, displayCode: c.displayCode, exp: c.exp })
        }
        const common = { mode: 'direct_post' as const, callbackURL: '/', onChallenge, signal: ac.signal }
        const result =
            kind === 'login'
                ? await authClient.signIn.concrnt(common)
                : await authClient.concrnt.addIdentity({ ...common, createSession: kind === 'register' })
        setWaiting(null)
        if (result.error) {
            const hint =
                result.error.code === 'IDENTITY_NOT_FOUND'
                    ? 'この CCID はまだ登録されていません。「Concrnt で新規登録」から始めてください'
                    : result.error.code === 'IDENTITY_ALREADY_REGISTERED'
                      ? 'この CCID は既に登録されています。「Concrnt でログイン」を使ってください'
                      : `${result.error.code ?? ''} ${result.error.message ?? ''}`
            setNotice({ tone: 'error', text: hint })
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
                if (kind === 'add') setNotice({ tone: 'info', text: 'CCID を追加しました' })
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
                    <button onClick={() => run('login')}>Concrnt でログイン</button>
                </p>
                <p>
                    <button onClick={() => run('register')}>Concrnt で新規登録</button>
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
                <small>user id: <code>{session.user.id}</code></small>
            </p>
            <Identities onAdd={() => run('add')} />
            <p>
                <button onClick={() => authClient.signOut()}>ログアウト</button>
            </p>
        </main>
    )
}

function Identities({ onAdd }: { onAdd: () => void }) {
    const { data, isPending, refetch } = authClient.useListIdentities()
    const rename = async (id: string, current: string | null | undefined) => {
        const name = prompt('ラベル', current ?? '')
        if (name === null) return
        await authClient.concrnt.updateIdentity({ id, name })
        void refetch()
    }
    const remove = async (id: string) => {
        if (!confirm('この CCID の紐付けを解除しますか?')) return
        await authClient.concrnt.deleteIdentity({ id })
        void refetch()
    }
    return (
        <section>
            <h2>紐付いた Concrnt アカウント</h2>
            {isPending && !data ? (
                <p>読み込み中...</p>
            ) : (
                <ul className="identities">
                    {(data ?? []).map((identity) => (
                        <li key={identity.id}>
                            <code>{identity.ccid}</code>
                            <br />
                            <small>
                                {identity.name ? `${identity.name} · ` : ''}@{identity.domain ?? '?'}
                            </small>
                            <br />
                            <button onClick={() => rename(identity.id, identity.name)}>改名</button> <button onClick={() => remove(identity.id)}>解除</button>
                        </li>
                    ))}
                </ul>
            )}
            <p>
                <button onClick={onAdd}>別の CCID を追加</button>
            </p>
        </section>
    )
}
