# @concrnt/auth-client

[CIP-17: External Service Authentication (Sign-In with Concrnt)](https://github.com/concrnt/CIPs) の
**RP (Relying Party) 側コア**ライブラリ。Concrnt のアカウントで外部サービスにログインさせたいときに、
Authorization Request の発行・応答の受理・ID Token の検証 (§9)・fragment の着地ページ・
ブラウザ側の待ち合わせをまとめて引き受ける。要求の内容はすべて Authorization Request URI に載り (by-value)、
Authenticator が RP に何かを取りに来ることは無い。

- ランタイム非依存 (Cloudflare Workers / Node 20+ / Deno / Bun)。Web 標準の `crypto` / `Response` と `TextEncoder` だけを使う
- HTTP フレームワークに依存しない。ルーティングとログイン後のセッションは利用側が組む
- **応答方式 (別端末の QR か、同一端末のリンクか) をサーバーは知らない**。選ぶのはブラウザで、サーバーは
  役割の固定された受け口を 2 つ持つだけ
- Concrnt サーバーには問い合わせない。ID Token の署名から CCID を復元して照合する
- **状態は小さなストアの行だけ**。要求ごとに 1 行を置き、応答を受理するときに原子的に消費する (nonce 一回限り)。
  秘密鍵は要らない

better-auth を使っているなら [`@concrnt/better-auth`](../better-auth/README.md) (このライブラリの上に乗ったプラグイン) の方が手早い。
`samples/auth-client/` に Cloudflare Workers + D1 + React の RP 実装例がある。

## インストール

```sh
pnpm add @concrnt/auth-client
```

## 使い方 (サーバー)

```ts
import { ConcrntAuth, AuthError, landingPage, parseAuthorizationResponse, type AuthStore } from '@concrnt/auth-client'

// 1. ストアを用意する。put / get / consume (原子的な取り出し) があれば何でもよい (SQLite/Postgres, Redis GETDEL, ...)
const store: AuthStore = {
    put: (key, value, expiresAt) => db.run('INSERT OR REPLACE INTO login_store VALUES (?, ?, ?)', key, value, expiresAt),
    get: (key) => db.get('SELECT value FROM login_store WHERE key = ? AND expires_at > ?', key, now()),
    consume: (key) => db.get('DELETE FROM login_store WHERE key = ? AND expires_at > ? RETURNING value', key, now())
}

const auth = new ConcrntAuth({
    origin: 'https://rp.example', // RP のオリジン。https 必須 (http://localhost だけ例外)
    store
    // redirectPath: '/auth/callback' (既定)。送り先 URL `${origin}${redirectPath}` が RP の識別子 (§5.1) で、ID Token の aud になる
    // scope: 'profile' (省略 = profile。'' で CCID のみ)、requestTtl: 300 (既定)
})

// 2. ログイン開始。結果をそのままブラウザに返す。応答方式はここでは決まらない
app.post('/api/login/start', async (c) => c.json(await auth.start()))
//   postUri     — QR にする URI (別端末)         fragmentUri — 同一端末のアプリを開くリンク
//   displayCode — 同意画面と見比べる絵文字       exp — 要求の失効時刻 (期限切れはブラウザが判断する)
//   pollToken   — ブラウザだけが知る秘密。別端末フローの結果を回収するのに使う。QR には載らない

// 3. 送り先 URL (POST /auth/callback): 別端末の Authenticator が form で id_token を POST してくる。
//    id_token の nonce で要求を引き、検証して「開始した人のため」に預かるだけ。送信者には何も発行しない
app.post('/auth/callback', async (c) => {
    await auth.receivePost(parseAuthorizationResponse(await c.req.formData()))
    return c.body(null, 204)
})

// 4. 同じ URL の GET (同一端末のアプリが 送り先 URL#id_token=… をブラウザで開いたとき): 着地ページを返す。
//    着地ページがフラグメントを 5 の exchange に JSON で送り、成功したら callbackURL へ遷移する
app.get('/auth/callback', (c) => landingPage({ exchangeUrl: '/api/login/exchange', callbackURL: '/' }))

// 5. 同一端末フロー: 着地ページが送ってきたフラグメントの内容を検証し、送ってきたブラウザにセッションを発行する
app.post('/api/login/exchange', async (c) => {
    const result = await auth.exchange(parseAuthorizationResponse(await c.req.json()))
    return result.status === 'ok' ? login(c, result.claims) : c.json({ status: 'denied' })
})

// 6. 別端末フローの回収: 開始したブラウザが pollToken で問い合わせる。結果は 1 回だけ返る
app.post('/api/login/status', async (c) => {
    const result = await auth.pollResult((await c.req.json()).pollToken)
    if (!result) return c.json({ status: 'pending' })
    return result.status === 'ok' ? login(c, result.claims) : c.json({ status: 'denied' })
})

// 失敗は AuthError。status に HTTP ステータスの目安が入っている (400 / 404)
app.onError((e, c) => (e instanceof AuthError ? c.json({ code: e.code, message: e.message }, e.status) : c.text('error', 500)))
```

`login(c, claims)` は RP 自身のセッション機構 (cookie など) で、`claims.sub` (CCID) に結び付ける (§9)。

**5 と 6 (セッションを発行するエンドポイント) は JSON の POST だけを受けること。** form を受けると cross-site の `<form>` で
他人の ID Token や結果を踏まされ、その人としてログインしてしまう (login CSRF)。JSON は cross-site からは送れない
(preflight で止まる)。GET も同様に不可 (トップレベル遷移で cookie が付く)。3 の post の受け口は form を受けるが、
誰にもセッションを発行しないので問題ない。

## 使い方 (ブラウザ)

`@concrnt/auth-client/browser` は Web 標準だけに依存し、サーバー側の依存を引かずに import できる。

```ts
import { runLogin } from '@concrnt/auth-client/browser'

const result = await runLogin({
    start: () => postJson('/api/login/start', {}),                   // ConcrntAuth.start() の結果をそのまま返す API
    poll: (pollToken) => postJson('/api/login/status', { pollToken }), // { status: 'pending' } か最終結果
    onChallenge: ({ postUri, fragmentUri, displayCode }) => {
        location.href = fragmentUri    // 同一端末: アプリがあればこれで開く (ユーザー操作の直後に)。無ければ何も起きない
        renderQr(postUri)              // 別端末: Authenticator が読む QR
        show(displayCode)              // 同意画面と見比べる絵文字 (§6)
    },
    signal: abortController.signal     // 「やめる」
})
// result.status: poll が返した最終結果 ('ok' | 'denied' …) | 'expired' | 'aborted'
```

- 別端末 (§8.1): `runLogin` が `poll` を繰り返し、結果が届けばそのブラウザにセッションが入る (サーバーの status が発行)
- 同一端末 (§8.2): アプリが `送り先 URL#id_token=…` を開く。その URL にはサーバーの着地ページ (`landingPage`) があり、
  フラグメントを exchange に送ってから `callbackURL` へ遷移する。フロントに着地の実装は要らない。拒否や失敗のときは
  `callbackURL?error=<code>` に戻る。別タブで完了した場合は `runLogin` には現れないので、必要なら利用側がセッションを
  確認して `signal` で中断する

## API

### `new ConcrntAuth<T>(options)`

`T` は要求ごとの付帯情報 (開始したユーザー・戻り先 URL など) の型。`start(context)` に渡したものが結果の `context` に戻る。

| オプション | 既定 | 意味 |
|---|---|---|
| `origin` | 必須 | RP のオリジン `scheme://host[:port]`。末尾スラッシュ・パス不可。https 以外は `http://localhost` / `127.0.0.1` だけ許す (ローカル開発用。その場合も識別子は https 表記) |
| `store` | 必須 | `AuthStore` (下記) |
| `redirectPath` | `/auth/callback` | 送り先 URL `${origin}${redirectPath}` のパス。この URL が RP の識別子 (§5.1) で、ID Token の `aud` と完全一致する。RP ごとに 1 本で要求ごとには変わらない |
| `scope` | なし (= `profile`) | URI の `s` (§5.2)。省略すると `s` を付けず `profile` 扱い。`''` で `s=` (CCID のみ) |
| `requestTtl` | 300 | 要求の行の有効期間 (秒)。この間に応答が届かなければ失効する。URI には載らない |
| `clockSkew` | 300 | ID Token の `exp` / `iat` 判定の時計ずれ許容幅 (秒) |
| `now` | `Date.now()/1000` | 現在時刻の供給元 (テスト用) |

| メソッド / フィールド | 役割 |
|---|---|
| `start(context?)` | §5。要求の行を 1 つ置き `StartedLogin { postUri, fragmentUri, displayCode, exp, pollToken }` を返す |
| `receivePost(params)` | §8.1。送り先 URL に届いた POST。`id_token` の nonce で要求を引き、検証・消費して結果を預ける。何も返さない (送信者にセッションを発行してはならない) |
| `exchange(params)` | §8.2。着地ページが送ってきたフラグメントの内容を検証・消費して `LoginResult` を返す。開始したブラウザには何も届かない |
| `pollResult(pollToken)` | §8.1。預けられた `LoginResult` を 1 回だけ取り出す。無ければ `null` |
| `redirectUri` | 送り先 URL `${origin}${redirectPath}` (RP が配信する URL) |
| `audience` | ID Token の `aud` の期待値 `https://<host>/<path>` (origin が `http://localhost` でも https 表記) |

`receivePost` と `exchange` はどちらも成功時に要求の行を原子的に消費する (§9 手順 7)。同じ要求への 2 回目以降の応答は、
経路を問わず `invalid_request` (404)、同時に届いた 2 件のうち負けた方は `request_used` (400)。検証に失敗した応答は消費しない。
どの要求への応答かは `id_token` の payload の `nonce` (署名検証の前に読む。検証は行を引いた後) か、拒否応答の `nonce` パラメータで決まる。

`LoginResult<T>` は `{ status: 'ok', claims: IdTokenClaims, idToken: string, context: T } | { status: 'denied', context: T }`。
セッションは `claims.sub` (CCID) に結び付けること (§9)。`name` / `picture` は Authenticator の自己申告で表示専用 (§7.3)。

### `AuthStore`

```ts
interface AuthStore {
    put(key: string, value: string, expiresAt: number): Promise<void> // expiresAt は UNIX 秒
    get(key: string): Promise<string | null>                          // 期限切れは null
    consume(key: string): Promise<string | null>                      // 期限内の値を原子的に取り出して消す
}
```

行は短命 (要求の有効期間 + 1 分) で、キーはランダム。一回限りの保証は `consume` の原子性に依る
(`DELETE … RETURNING`、Redis `GETDEL`、better-auth の `consumeVerificationValue` など)。原子的な取り出しが無いストア
(Cloudflare KV など) では、同じ要求への同時応答が両方通りうる。`MemoryStore` (単一プロセス用の参照実装) を同梱している。

### `landingPage({ exchangeUrl, callbackURL?, texts? })`

§8.2 の着地ページの `Response`。`Cache-Control: no-store`・`Referrer-Policy: no-referrer`・スクリプト自身のハッシュだけを許す
CSP 付き。スクリプトは固定文字列で、exchange の URL・戻り先・文言は `<html>` の data 属性で渡す。`exchangeUrl` には
`{ id_token, error, nonce }` を JSON で POST し、`{ status: 'ok' | 'denied', callbackURL? }` (失敗時は `{ code?, message?, callbackURL? }`) を期待する。
`renderLanding` (HTML だけ)・`LANDING_SCRIPT`・`landingScriptHash()` も export している。

### `runLogin(options)` (`@concrnt/auth-client/browser`)

`{ start, poll, onChallenge?, pollIntervalMs? = 2000, signal?, now? }`。`start` の結果を `onChallenge` に渡し (pollToken は渡さない)、
`poll` が `pending` 以外を返すまで繰り返す。`exp` を過ぎれば `{ status: 'expired' }`、`signal` で `{ status: 'aborted' }`。
`start` / `poll` の例外はそのまま伝わる。

### その他

- `authorizationRequestUri(redirectUri, mode, nonce, scope?)` — 送り先 URL `https://<host>/<path>` を `concrnt-auth://<mode>/<host>/<path>?n=<nonce>[&s=<scope>]` にする (§5.2)。`start()` が両方返すので通常は不要
- `audienceOf(redirectUri)` — 送り先 URL から ID Token の `aud` の期待値 (`https://<host>/<path>`) を作る
- `parseAuthorizationResponse(FormData | URLSearchParams | object)` — form / フラグメント / JSON body から `{ id_token, error, nonce }` を取り出す (他は無視)
- `peekIdTokenNonce(token)` — 署名検証の前に payload の `nonce` だけ読む (要求の行を引くため)。JWT の形でなければ `null`
- `verifyIdToken(token, { audience, nonce, now?, clockSkew? })` — §9 手順 1・3〜6 の単体。`aud` は `audience` と完全一致、`exp = iat + 300` を確認する
- `emojihash(value)` — `display_code` の絵文字フィンガープリント (CIP-17 付録 A。`@concrnt/worldlib` と同じ表・同じアルゴリズム)。`displayCode = emojihash(nonce)`
- `AuthError { code, status }` — `invalid_option` / `invalid_request` / `request_used` / `missing_id_token` / `missing_nonce` / `invalid_id_token`

## 中で何をしているか

RP が持つ状態はストアの行だけで、どれも数分で消える。

- **要求の行** `concrnt-auth:request:<nonce>` = `{ exp, pollHash, context }` (expiresAt = exp)。
  `nonce` は 16 バイトの乱数 (base64url 22 文字) で、Authorization Request URI の `n` に載り、ID Token の `nonce` として署名の内側に戻ってくる。
  行のキーがそのまま応答の対応付けになる (`state` も要求ごとの URL も使わない)。
  `pollHash` はブラウザ秘密 `pollToken` の SHA-256 で、別端末フローの結果の宛先になる。`pollToken` 自体は QR にもストアにも載らないので、
  QR を見た第三者は結果を取れない (§8.1)
- **要求は by-value** — Authorization Request URI は `concrnt-auth://<mode>/<host>/<redirectPath>?n=<nonce>` (70〜90 バイト前後) で、
  Authenticator はこれだけで同意画面を出す。RP のエンドポイントを GET することは無いので、同意前に Authenticator の IP/UA が RP に渡らない。
  `display_code` は RP も Authenticator も `emojihash(nonce)` で導出する (付録 A)
- **応答方式はサーバーに現れない** — `start()` が両方の `<mode>` の URI を返す。Authenticator は URI の `<mode>` に従って配送し、
  post のときだけ `display_code` の照合と別端末である旨の提示を出す
- **aud は送り先 URL そのもの** — オリジンではない。攻撃者が `<path>` に RP オリジン上のオープンリダイレクタを指定して fragment の
  トークンを横取りしても、`aud` が本物の送り先 URL と一致しないので使えない (§10)
- **受け口の役割が固定** — 送り先 URL への POST は「開始した人のために預かる」。`exchange` (fragment) は
  「提示した人をログインさせる」。どちらが来たかを判定したり、開始ブラウザとの一致を照合したりしない。
  他人に fragment のリンクを踏ませても、その人が自分のアカウントでログインするだけで、リンクを作った側には何も届かない (§10.1)
- **一回限り** (§9 手順 7) — 応答を受理するときに要求の行を `consume` で原子的に消し、以後は経路を問わず拒否する。
  QR とリンクは同じ要求なので、片方で成立すればもう片方も使えない。`exchange` は提示者をログインさせるので、有効期間内の ID Token は
  その要求に対する bearer になる。消費が無いと漏れた ID Token で 2 人目がログインできてしまう
- **偽造 URI は無害** — 誰でも任意の `n` で URI を作れるが、そのトークンは正規の送り先 URL に届いて行が無いので 404 で捨てられる。
  `aud` もその RP なので他所でも使えない
- **結果の行** `concrnt-auth:result:<pollHash>` = `LoginResult` (expiresAt = exp + 60)。`pollResult` が `consume` で 1 回だけ取り出す。
  要求の失効後も 1 分は回収できる

## 開発

```sh
pnpm install
pnpm build        # dist/
pnpm test         # vitest (テスト内に最小の Authenticator を持ち、§9 の各失敗系まで通す)
pnpm lint
```

## 今後の候補

- CIP-18 (Service Key Certificate)
