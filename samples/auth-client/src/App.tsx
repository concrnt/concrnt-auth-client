// CIP-17 RP のブラウザ側。流れ (開始 → QR / リンク → 応答待ち) は @concrnt/auth-client/browser の runLogin に任せ、
// ここには fetch の形と画面だけがある。
//   ログインボタン 1 つで両方の経路を同時に始める:
//   同一端末 (§8.2): fragmentUri に遷移して同じ端末のアプリを開く。アプリが開く /auth/callback#id_token=… は
//                    Worker の着地ページが受け、このブラウザにログイン cookie を発行して / に戻す (フロントの実装は不要)
//   別端末   (§8.1): アプリが開かなかった場合に備えて postUri の QR も表示し、runLogin が status をポーリングして待つ
import { useEffect, useState } from 'react'
import QRCode from 'qrcode'
import { runLogin, type LoginChallenge, type LoginStartResponse } from '@concrnt/auth-client/browser'

interface User {
    ccid: string
    domain: string
    name?: string
    picture?: string
}

type Waiting = { qr: string; fragmentUri: string; displayCode: string; exp: number }
type Notice = { tone: 'info' | 'error'; text: string }
type StatusResponse = { status: 'pending' } | { status: 'denied' } | { status: 'ok'; user: User }

const postJson = async <T,>(url: string, body: unknown): Promise<T> => {
    const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
    if (!res.ok) throw new Error(`${res.status} ${await res.text()}`)
    return (await res.json()) as T
}

const fetchMe = async (): Promise<User | null> => {
    const res = await fetch('/api/me')
    return res.ok ? ((await res.json()) as User) : null
}

export default function App() {
    const [user, setUser] = useState<User | null | undefined>(undefined) // undefined = 初回取得中
    const [waiting, setWaiting] = useState<Waiting | null>(null)
    const [abort, setAbort] = useState<AbortController | null>(null)
    // 着地ページが ?error= を付けて戻してきた場合は初期表示で拾い、URL からは消す
    const [notice, setNotice] = useState<Notice | null>(() => {
        const error = new URLSearchParams(location.search).get('error')
        if (!error) return null
        history.replaceState(null, '', '/')
        return { tone: 'error', text: error === 'access_denied' ? 'ログインが拒否されました' : `ログインに失敗しました (${error})` }
    })

    useEffect(() => {
        void fetchMe().then(setUser)
    }, [])

    // 待機中: 同一端末フローが別タブで完了していれば cookie が付いているので、このタブも追従して待機を打ち切る
    useEffect(() => {
        if (!waiting) return
        const timer = setInterval(async () => {
            const me = await fetchMe()
            if (me) {
                setUser(me)
                abort?.abort()
            }
        }, 3000)
        return () => clearInterval(timer)
    }, [waiting, abort])

    const login = async () => {
        setNotice(null)
        const ac = new AbortController()
        setAbort(ac)
        // 応答方式を選ぶのはここ: QR は post、同一端末で開くリンクは fragment。同じ要求から両方作られる
        const onChallenge = async (c: LoginChallenge) => {
            // カスタムスキームへの遷移はユーザー操作の直後でないとブラウザに止められる。アプリが無い端末では何も起きない
            location.href = c.fragmentUri
            setWaiting({ qr: await QRCode.toDataURL(c.postUri), fragmentUri: c.fragmentUri, displayCode: c.displayCode, exp: c.exp })
        }
        try {
            const result = await runLogin<Exclude<StatusResponse, { status: 'pending' }>>({
                start: () => postJson<LoginStartResponse>('/api/login/start', {}),
                poll: (pollToken) => postJson<StatusResponse>('/api/login/status', { pollToken }),
                onChallenge,
                signal: ac.signal
            })
            switch (result.status) {
                case 'ok':
                    setUser(result.user)
                    break
                case 'denied':
                    setNotice({ tone: 'error', text: 'ログインが拒否されました' })
                    break
                case 'expired':
                    setNotice({ tone: 'error', text: 'ログイン要求の有効期限が切れました' })
                    break
                case 'aborted':
                    break
            }
        } catch (e) {
            setNotice({ tone: 'error', text: `ログインに失敗しました (${(e as Error).message})` })
        } finally {
            setWaiting(null)
        }
    }

    const logout = async () => {
        await fetch('/api/logout', { method: 'POST' })
        setUser(null)
    }

    if (user === undefined) return <p>読み込み中...</p>

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

    if (!user) {
        return (
            <main>
                <h1>Sign-In with Concrnt サンプル</h1>
                {notice && <p className={notice.tone}>{notice.text}</p>}
                <p>
                    <button onClick={login}>Concrnt でログイン</button>
                </p>
            </main>
        )
    }

    return (
        <main>
            <h1>ログインしました</h1>
            {user.picture && <img src={user.picture} alt="" width={64} height={64} />}
            <p>{user.name ?? '(名前なし)'}</p>
            <p>
                <code>{user.ccid}</code>
                <br />
                <small>@{user.domain}</small>
            </p>
            <button onClick={logout}>ログアウト</button>
        </main>
    )
}
