# @concrnt/auth-client

[CIP-17: External Service Authentication (Sign-In with Concrnt)](https://github.com/concrnt/CIPs) の
**RP (Relying Party) 側コア**ライブラリ。Concrnt のアカウントで外部サービスにログインさせたいときに、
Authorization Request の発行・Request Object の提供・応答の受理・ID Token の検証 (§9)・fragment の着地ページ・
ブラウザ側の待ち合わせをまとめて引き受ける。

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
    origin: 'https://rp.example', // RP のオリジン (§5.1)。https 必須 (http://localhost だけ例外)
    store,
    clientMetadata: { client_name: 'Example Service' }
    // requestPath: '/auth/request', redirectPath: '/auth/callback', requestTtl: 300 (既定)
})

// 2. ログイン開始。結果をそのままブラウザに返す。応答方式はここでは決まらない
app.post('/api/login/start', async (c) => c.json(await auth.start()))
//   directPostUri — QR にする URI (別端末)       fragmentUri — 同一端末のアプリを開くリンク
//   displayCode   — 同意画面と見比べる絵文字     exp — 失効時刻 (期限切れはブラウザが判断する)
//   pollToken     — ブラウザだけが知る秘密。別端末フローの結果を回収するのに使う。QR には載らない

// 3. request_uri (GET /auth/request/<C>): Request Object を返す。CORS * が必要
app.get('/auth/request/:challenge', async (c) => c.json(await auth.getRequestObject(c.params.challenge)))

// 4. redirect_uri (POST /auth/callback/<C>): 別端末の Authenticator が form で direct_post してくる。
//    検証して「開始した人のため」に預かるだけ。送信者には何も発行しない
app.post('/auth/callback/:challenge', async (c) => {
    await auth.receiveDirectPost(c.params.challenge, parseAuthorizationResponse(await c.req.formData()))
    return c.body(null, 204)
})

// 5. 同じ URL の GET (同一端末のアプリが redirect_uri#id_token=… をブラウザで開いたとき): 着地ページを返す。
//    着地ページがフラグメントを 6 の exchange に JSON で送り、成功したら callbackURL へ遷移する
app.get('/auth/callback/:challenge', (c) => landingPage({ exchangeUrl: `/api/login/exchange/${c.params.challenge}`, callbackURL: '/' }))

// 6. 同一端末フロー: 着地ページが送ってきたフラグメントの内容を検証し、送ってきたブラウザにセッションを発行する
app.post('/api/login/exchange/:challenge', async (c) => {
    const result = await auth.exchange(c.params.challenge, parseAuthorizationResponse(await c.req.json()))
    return result.status === 'ok' ? login(c, result.claims) : c.json({ status: 'denied' })
})

// 7. 別端末フローの回収: 開始したブラウザが pollToken で問い合わせる。結果は 1 回だけ返る
app.post('/api/login/status', async (c) => {
    const result = await auth.pollResult((await c.req.json()).pollToken)
    if (!result) return c.json({ status: 'pending' })
    return result.status === 'ok' ? login(c, result.claims) : c.json({ status: 'denied' })
})

// 失敗は AuthError。status に HTTP ステータスの目安が入っている (400 / 404)
app.onError((e, c) => (e instanceof AuthError ? c.json({ code: e.code, message: e.message }, e.status) : c.text('error', 500)))
```

`login(c, claims)` は RP 自身のセッション機構 (cookie など) で、`claims.sub` (CCID) に結び付ける (§9)。

**6 と 7 (セッションを発行するエンドポイント) は JSON の POST だけを受けること。** form を受けると cross-site の `<form>` で
他人の ID Token や結果を踏まされ、その人としてログインしてしまう (login CSRF)。JSON は cross-site からは送れない
(preflight で止まる)。GET も同様に不可 (トップレベル遷移で cookie が付く)。4 の direct_post の受け口は form を受けるが、
誰にもセッションを発行しないので問題ない。

## 使い方 (ブラウザ)

`@concrnt/auth-client/browser` は Web 標準だけに依存し、サーバー側の依存を引かずに import できる。

```ts
import { runLogin } from '@concrnt/auth-client/browser'

const result = await runLogin({
    start: () => postJson('/api/login/start', {}),                   // ConcrntAuth.start() の結果をそのまま返す API
    poll: (pollToken) => postJson('/api/login/status', { pollToken }), // { status: 'pending' } か最終結果
    onChallenge: ({ directPostUri, fragmentUri, displayCode }) => {
        location.href = fragmentUri    // 同一端末: アプリがあればこれで開く (ユーザー操作の直後に)。無ければ何も起きない
        renderQr(directPostUri)        // 別端末: Authenticator が読む QR
        show(displayCode)              // 同意画面と見比べる絵文字 (§6)
    },
    signal: abortController.signal     // 「やめる」
})
// result.status: poll が返した最終結果 ('ok' | 'denied' …) | 'expired' | 'aborted'
```

- 別端末 (§8.1): `runLogin` が `poll` を繰り返し、結果が届けばそのブラウザにセッションが入る (サーバーの status が発行)
- 同一端末 (§8.2): アプリが `redirect_uri#id_token=…` を開く。その URL にはサーバーの着地ページ (`landingPage`) があり、
  フラグメントを exchange に送ってから `callbackURL` へ遷移する。フロントに着地の実装は要らない。拒否や失敗のときは
  `callbackURL?error=<code>` に戻る。別タブで完了した場合は `runLogin` には現れないので、必要なら利用側がセッションを
  確認して `signal` で中断する

## API

### `new ConcrntAuth<T>(options)`

`T` は要求ごとの付帯情報 (開始したユーザー・戻り先 URL など) の型。`start(context)` に渡したものが結果の `context` に戻る。

| オプション | 既定 | 意味 |
|---|---|---|
| `origin` | 必須 | RP のオリジン `scheme://host[:port]` (§5.1)。末尾スラッシュ・パス不可。https 以外は `http://localhost` だけ許す |
| `store` | 必須 | `AuthStore` (下記) |
| `requestPath` | `/auth/request` | `request_uri = ${origin}${requestPath}/${C}` |
| `redirectPath` | `/auth/callback` | `redirect_uri = ${origin}${redirectPath}/${C}` (§5.3)。要求ごとに異なり、応答がどの要求のものかはこの URL で決まる |
| `clientMetadata` | なし | `client_name` / `logo_uri` / `policy_uri` / `tos_uri` (§5.3) |
| `requestTtl` | 300 | Request Object の有効期間 (秒) |
| `clockSkew` | 300 | ID Token の `iat` 判定の許容幅 (秒) |
| `now` | `Date.now()/1000` | 現在時刻の供給元 (テスト用) |

| メソッド | 役割 |
|---|---|
| `start(context?)` | §5。要求の行を 1 つ置き `StartedLogin { challenge, requestUri, directPostUri, fragmentUri, displayCode, exp, pollToken }` を返す |
| `getRequestObject(C)` | §5.3。両方式で同じ内容。無い・期限切れ・応答済みは `AuthError('invalid_request', 404)` |
| `receiveDirectPost(C, params)` | §8.1。redirect_uri (末尾が C) に届いた direct_post を検証し、要求を消費して結果を預ける。何も返さない (送信者にセッションを発行してはならない) |
| `exchange(C, params)` | §8.2。着地ページが送ってきたフラグメントの内容を検証し、要求を消費して `LoginResult` を返す。開始したブラウザには何も届かない |
| `pollResult(pollToken)` | §8.1。預けられた `LoginResult` を 1 回だけ取り出す。無ければ `null` |
| `redirectUriFor(C)` | `${origin}${redirectPath}/${C}` |

`receiveDirectPost` と `exchange` はどちらも成功時に要求の行を原子的に消費する (§9 手順 3)。同じ要求への 2 回目以降の応答は、
経路を問わず `invalid_request` (404)、同時に届いた 2 件のうち負けた方は `request_used` (400)。検証に失敗した応答は消費しない。

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
`{ id_token, error }` を JSON で POST し、`{ status: 'ok' | 'denied', callbackURL? }` (失敗時は `{ code?, message?, callbackURL? }`) を期待する。
`renderLanding` (HTML だけ)・`LANDING_SCRIPT`・`landingScriptHash()` も export している。

### `runLogin(options)` (`@concrnt/auth-client/browser`)

`{ start, poll, onChallenge?, pollIntervalMs? = 2000, signal?, now? }`。`start` の結果を `onChallenge` に渡し (pollToken は渡さない)、
`poll` が `pending` 以外を返すまで繰り返す。`exp` を過ぎれば `{ status: 'expired' }`、`signal` で `{ status: 'aborted' }`。
`start` / `poll` の例外はそのまま伝わる。

### その他

- `authorizationRequestUri(requestUri, mode)` — `https://<host>/<path>` を `concrnt-auth://<mode>/<host>/<path>` にする (§5.2)。`start()` が両方返すので通常は不要
- `parseAuthorizationResponse(FormData | URLSearchParams | object)` — form / フラグメント / JSON body から `{ id_token, error }` を取り出す (他は無視)
- `verifyIdToken(token, { origin, nonce, now?, clockSkew? })` — §9 手順 1〜6 の単体。ConcrntAuth を使わず検証だけしたいとき
- `emojihash(value)` — `display_code` の絵文字フィンガープリント (`@concrnt/worldlib` と同じ表・同じアルゴリズム)
- `AuthError { code, status }` — `invalid_option` / `invalid_request` / `request_used` / `missing_id_token` / `invalid_id_token`

## 中で何をしているか

RP が持つ状態はストアの行だけで、どれも数分で消える。

- **要求の行** `concrnt-auth:request:<C>` = `{ nonce, exp, pollHash, context }` (expiresAt = exp)。
  C は 16 バイトの乱数 (base64url 22 文字) で、`request_uri` のパス末尾と Request Object の `redirect_uri` のパス末尾に載せる
  (`state` は使わない。応答がどの要求のものかは届いた URL で決まる)。`nonce` は 32 バイトの乱数で行に置き、応答の ID Token と照合する。
  `pollHash` はブラウザ秘密 `pollToken` の SHA-256 で、別端末フローの結果の宛先になる。`pollToken` 自体は QR にもストアにも載らないので、
  QR を見た第三者は結果を取れない (§8.1)
- **応答方式はサーバーに現れない** — Authorization Request URI は `concrnt-auth://<mode>/<host>/<requestPath>/<C>` (80〜100 バイト前後) で、
  `start()` が両方の `<mode>` の URI を返す。Request Object は両方式で同一 (`response_mode` 無し、`display_code` 常時)。
  Authenticator は URI の `<mode>` に従って配送し、direct_post のときだけ `display_code` と別端末警告を出す
- **受け口の役割が固定** — `redirect_uri` への POST (direct_post) は「開始した人のために預かる」。`exchange` (fragment) は
  「提示した人をログインさせる」。どちらが来たかを判定したり、開始ブラウザとの一致を照合したりしない。
  他人に fragment のリンクを踏ませても、その人が自分のアカウントでログインするだけで、リンクを作った側には何も届かない (§10.1)
- **一回限り** (§9 手順 3) — 応答を受理するときに要求の行を `consume` で原子的に消し、以後は経路を問わず拒否する。
  QR とリンクは同じ要求なので、片方で成立すればもう片方も使えない。`exchange` は提示者をログインさせるので、有効期間内の ID Token は
  その要求に対する bearer になる。消費が無いと漏れた ID Token で 2 人目がログインできてしまう
- **結果の行** `concrnt-auth:result:<pollHash>` = `LoginResult` (expiresAt = exp + 60)。`pollResult` が `consume` で 1 回だけ取り出す。
  要求の失効後も 1 分は回収できる
- **`request_uri` は再取得できる** — §5.2 の一回限りは SHOULD。Request Object に QR 保持者が知らない情報は含まれないので、
  `exp` の短さで受け入れている

## 開発

```sh
pnpm install
pnpm build        # dist/
pnpm test         # vitest (テスト内に最小の Authenticator を持ち、§9 の各失敗系まで通す)
pnpm lint
```

## 今後の候補

- CIP-18 (Service Key Certificate)
