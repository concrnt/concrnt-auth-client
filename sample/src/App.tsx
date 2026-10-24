// CIP-17 RP のブラウザ側。ログインボタンは 1 つで、押すと両方の経路を同時に始める:
//   同一端末 (§8.2): concrnt-auth://fragment/… に遷移して同じ端末のアプリを開く。
//                    アプリが開く /auth/callback#id_token=… をこのブラウザで受け取り、
//                    フラグメントの内容をそのまま /api/login/session に送って、このブラウザがログインする
//   別端末   (§8.1): アプリが開かなかった場合に備えて concrnt-auth://direct_post/… の QR も表示し、
//                    応答を Worker 経由でポーリングで待つ
// どちらの URI も同じ requestUri から作る。応答方式を選ぶのはここ (ブラウザ) で、サーバーは知らない
import { useEffect, useRef, useState } from 'react'
import QRCode from 'qrcode'
import { authorizationRequestUri } from '@concrnt/auth-client'

interface User {
    ccid: string
    domain: string
    name?: string
    picture?: string
}

type Phase =
    | { kind: 'loading' }
    | { kind: 'loggedOut' }
    | { kind: 'waiting'; session: string; exp: number; qr: string; displayCode: string }
    | { kind: 'loggedIn'; user: User }
    | { kind: 'denied' }
    | { kind: 'expired' }
    | { kind: 'failed'; reason: string }

// サーバーは @concrnt/auth-client の start() の結果をそのまま返す (StartedLogin)
interface StartResponse {
    session: string
    displayCode: string
    exp: number
    requestUri: string
}

export default function App() {
    const [phase, setPhase] = useState<Phase>({ kind: 'loading' })
    const booted = useRef(false)

    useEffect(() => {
        if (booted.current) return
        booted.current = true

        // §8.2: アプリがブラウザで開いた /auth/callback#id_token=…&state=… (拒否時は #error=access_denied&state=…)
        if (location.pathname === '/auth/callback') {
            const params = new URLSearchParams(location.hash.slice(1))
            history.replaceState(null, '', '/') // ID Token を URL に残さない
            // フラグメントの内容をそのまま送る。検証が通れば、このブラウザにログイン cookie が発行される
            fetch('/api/login/session', { method: 'POST', body: params }).then(async (res) => {
                if (!res.ok) setPhase({ kind: 'failed', reason: await res.text() })
                else {
                    const result = await res.json()
                    if (result.status === 'ok') setPhase({ kind: 'loggedIn', user: result.user })
                    else setPhase({ kind: 'denied' })
                }
            })
            return
        }

        // cookie で既にログイン済みか確認する
        fetch('/api/me').then(async (res) => {
            setPhase(res.ok ? { kind: 'loggedIn', user: await res.json() } : { kind: 'loggedOut' })
        })
    }, [])

    // QR 表示中: ブラウザだけが知る session でポーリングし、結果を受け取る (§8.1)
    useEffect(() => {
        if (phase.kind !== 'waiting') return
        const timer = setInterval(async () => {
            // 同一端末フローが別タブで完了していれば cookie が付いているので、このタブも追従する
            const me = await fetch('/api/me')
            if (me.ok) {
                setPhase({ kind: 'loggedIn', user: await me.json() })
                return
            }
            // サーバーは開始時に何も記録していないので、期限切れはこちらで判断する
            if (Date.now() / 1000 > phase.exp) {
                setPhase({ kind: 'expired' })
                return
            }
            const res = await fetch(`/api/login/status?session=${phase.session}`)
            const result = await res.json()
            if (result.status === 'ok') setPhase({ kind: 'loggedIn', user: result.user })
            if (result.status === 'denied') setPhase({ kind: 'denied' })
        }, 2000)
        return () => clearInterval(timer)
    }, [phase])

    // ボタン押下で要求を 1 往復で作り、同じ requestUri から同一端末用 (fragment) と QR 用 (direct_post) の URI を組む。
    // カスタムスキームへの遷移はユーザー操作の直後 (transient activation の間) でないとブラウザに止められる
    const login = async () => {
        const res = await fetch('/api/login/start', { method: 'POST' })
        const start = (await res.json()) as StartResponse
        location.href = authorizationRequestUri(start.requestUri, 'fragment') // アプリが無い端末では何も起きない
        const qr = await QRCode.toDataURL(authorizationRequestUri(start.requestUri, 'direct_post'))
        setPhase({ kind: 'waiting', session: start.session, exp: start.exp, qr, displayCode: start.displayCode })
    }

    const logout = async () => {
        await fetch('/api/logout', { method: 'POST' })
        setPhase({ kind: 'loggedOut' })
    }

    switch (phase.kind) {
        case 'loading':
            return <p>読み込み中...</p>
        case 'loggedOut':
            return (
                <main>
                    <h1>Sign-In with Concrnt サンプル</h1>
                    <p>
                        <button onClick={login}>Concrnt でログイン</button>
                    </p>
                </main>
            )
        case 'waiting':
            return (
                <main>
                    <h1>Concrnt アプリで承認してください</h1>
                    <p>
                        <small>アプリが開かなかった場合は、別の端末の Concrnt アプリでこの QR コードを読み取ってください</small>
                    </p>
                    <img src={phase.qr} alt="Authorization Request QR" width={256} height={256} />
                    <p>
                        照合コード
                        <br />
                        <span style={{ fontSize: '2rem' }}>{phase.displayCode}</span>
                        <br />
                        <small>アプリの同意画面に同じ絵文字が表示されます</small>
                    </p>
                    <p>応答を待っています...</p>
                </main>
            )
        case 'loggedIn':
            return (
                <main>
                    <h1>ログインしました</h1>
                    {phase.user.picture && <img src={phase.user.picture} alt="" width={64} height={64} />}
                    <p>{phase.user.name ?? '(名前なし)'}</p>
                    <p>
                        <code>{phase.user.ccid}</code>
                        <br />
                        <small>@{phase.user.domain}</small>
                    </p>
                    <button onClick={logout}>ログアウト</button>
                </main>
            )
        case 'denied':
        case 'expired':
        case 'failed':
            return (
                <main>
                    <h1>
                        {phase.kind === 'denied'
                            ? 'ログインが拒否されました'
                            : phase.kind === 'expired'
                              ? 'ログイン要求の有効期限が切れました'
                              : 'ログインに失敗しました'}
                    </h1>
                    {phase.kind === 'failed' && <p><small>{phase.reason}</small></p>}
                    <button onClick={() => setPhase({ kind: 'loggedOut' })}>最初に戻る</button>
                </main>
            )
    }
}
