# @concrnt/auth-client

[CIP-17: External Service Authentication (Sign-In with Concrnt)](https://github.com/concrnt/CIPs) の
**RP (Relying Party) 側コア**ライブラリ。Concrnt のアカウントで外部サービスにログインさせたいときに、
Authorization Request の発行・Request Object の提供・応答の受理・ID Token の検証 (§9) をまとめて引き受ける。

- ランタイム非依存 (Cloudflare Workers / Node 20+ / Deno / Bun)。Web 標準の `crypto` と `TextEncoder` だけを使う
- HTTP フレームワークに依存しない。ルーティングとログイン後のセッションは利用側が組む
- **応答方式 (別端末の QR か、同一端末のリンクか) をサーバーは知らない**。選ぶのはブラウザで、サーバーは
  役割の固定された受け口を 2 つ持つだけ
- Concrnt サーバーには問い合わせない。ID Token の署名から CCID を復元して照合する
- **できるだけ状態を持たない**。要求は HMAC 付きチャレンジとして Authenticator を経由して戻ってくるので保存しない。
  残る状態は HMAC 鍵と小さなストア (`AuthStore`: 別端末フローのメールボックスと、応答済みチャレンジの記録) だけ

`sample/` に Cloudflare Workers + React の RP 実装例がある (下記)。

## インストール

```sh
pnpm add @concrnt/auth-client
```

## 使い方

```ts
import { ConcrntAuth, AuthError, parseAuthorizationResponse, type AuthStore } from '@concrnt/auth-client'

// 1. ストアを用意する。get / set(ttl) / delete があれば何でもよい (KV, Redis, Postgres, ...)。
//    メールボックスの中身はライブラリが署名した封筒なので、改ざん耐性も強整合も要らない
const store: AuthStore = {
    get: (key) => kv.get(key),
    set: (key, value, ttlSeconds) => kv.put(key, value, { expirationTtl: ttlSeconds }),
    delete: (key) => kv.delete(key)
}

const auth = new ConcrntAuth({
    origin: 'https://rp.example', // RP のオリジン (§5.1)。https 必須 (http://localhost だけ例外)
    secret: env.LOGIN_SECRET, // HMAC 鍵
    store,
    clientMetadata: { client_name: 'Example Service' }
    // requestPath: '/auth/request', redirectPath: '/auth/callback', requestTtl: 300 (既定)
})

// 2. ログイン開始。結果をそのままブラウザに返す。応答方式はここでは決まらない
app.post('/api/login/start', (c) => c.json(auth.start()))
//   session     — ブラウザだけが知る秘密。別端末フローの結果を回収するのに使う。QR には載せない
//   displayCode — 同意画面と見比べる絵文字
//   exp         — 失効時刻。RP は何も保存しないので期限切れはブラウザが判断する
//   requestUri  — https://rp.example/auth/request/<C>。ブラウザがこれを concrnt-auth:// にする

// 3. request_uri (GET https://rp.example/auth/request/<C>): Request Object を返す。CORS * が必要
app.get('/auth/request/:challenge', (c) => c.json(auth.getRequestObject(c.params.challenge)))

// 4. redirect_uri (POST https://rp.example/auth/callback/<C>): 別端末の Authenticator が direct_post してくる。
//    どの要求への応答かは URL の C で決まる。検証して「開始した人のため」に預かるだけ。送信者には何も発行しない
app.post('/auth/callback/:challenge', async (c) => {
    await auth.receiveDirectPost(c.params.challenge, parseAuthorizationResponse(await c.req.formData()))
    return c.body(null, 204)
})

// 5. 別端末フローの回収: 開始したブラウザが session でポーリングする。読んだら消える
app.get('/api/login/status', async (c) => {
    const result = await auth.pollResult(c.req.query('session'))
    if (!result) return c.json({ status: 'pending' })
    return result.status === 'ok' ? login(c, result.claims) : c.json({ status: 'denied' })
})

// 6. 同一端末フロー: redirect_uri#id_token=… で開かれたブラウザが、開かれた URL の C とフラグメントの内容をそのまま送ってくる。
//    検証して、送ってきたブラウザにセッションを発行する。メールボックスには触らない
app.post('/api/login/session/:challenge', async (c) => {
    const result = await auth.exchange(c.params.challenge, parseAuthorizationResponse(await c.req.formData()))
    return result.status === 'ok' ? login(c, result.claims) : c.json({ status: 'denied' })
})

// 失敗は AuthError。status に HTTP ステータスの目安が入っている (400 / 404)
app.onError((e, c) => (e instanceof AuthError ? c.text(e.message, e.status) : c.text('error', 500)))
```

`login(c, claims)` は RP 自身のセッション機構 (cookie など) で、`claims.sub` (CCID) に結び付ける (§9)。

### ブラウザ側で必要なこと

ライブラリは今のところサーバー側のコアだけで、ブラウザ側のコードは含まない (`authorizationRequestUri` だけは
純関数なのでブラウザからも import できる)。RP のフロントがやることは:

1. ログインボタン押下で `start` の API を叩き、`requestUri` から 2 つの URI を作る。
   `authorizationRequestUri(requestUri, 'fragment')` へ `location.href` で遷移しつつ (同じ端末にアプリがあれば開く。
   無ければ何も起きない)、`authorizationRequestUri(requestUri, 'direct_post')` を QR にして `displayCode` と一緒に表示する。
   先に応答が返った方でログインが成立する。カスタムスキームへの遷移はユーザー操作の直後でないとブラウザに止められる
2. `session` でポーリングして結果を待つ (別端末)。`exp` を過ぎたら期限切れ表示にする
3. `/auth/callback/<C>#id_token=…` (または `#error=access_denied`) で開かれたら、フラグメントを URL から消し、
   URL の `<C>` とフラグメントの内容をそのまま `exchange` の API に送る (同一端末)。
   成功すれば**このブラウザ**がログインする。開始したブラウザと同じである必要はない

`sample/src/App.tsx` がそのまま参考になる。

## API

### `new ConcrntAuth(options)`

| オプション | 既定 | 意味 |
|---|---|---|
| `origin` | 必須 | RP のオリジン `scheme://host[:port]` (§5.1)。末尾スラッシュ・パス不可。https 以外は `http://localhost` だけ許す |
| `secret` | 必須 | HMAC 鍵。チャレンジの MAC、nonce の導出、メールボックス封筒の署名に使う |
| `store` | 必須 | `AuthStore` (下記)。メールボックスと応答済みチャレンジの記録に使う |
| `requestPath` | `/auth/request` | `request_uri = ${origin}${requestPath}/${C}` |
| `redirectPath` | `/auth/callback` | `redirect_uri = ${origin}${redirectPath}/${C}` (§5.3)。要求ごとに異なり、応答がどの要求のものかはこの URL で決まる |
| `clientMetadata` | なし | `client_name` / `logo_uri` / `policy_uri` / `tos_uri` (§5.3) |
| `requestTtl` | 300 | Request Object の有効期間 (秒) |
| `clockSkew` | 300 | ID Token の `iat` 判定の許容幅 (秒) |
| `now` | `Date.now()/1000` | 現在時刻の供給元 (テスト用) |

| メソッド | 役割 |
|---|---|
| `start()` | §5。`StartedLogin { session, displayCode, exp, challenge, requestUri }`。応答方式に依存せず、何も保存しない |
| `getRequestObject(challenge)` | §5.3。C から Request Object を再構築。両方式で同じ内容。不正・期限切れは `AuthError('invalid_request', 404)` |
| `receiveDirectPost(challenge, params)` | §8.1。redirect_uri (末尾が C) に届いた direct_post を検証し、開始したブラウザのメールボックスに置く。何も返さない (送信者にセッションを発行してはならない) |
| `exchange(challenge, params)` | §8.2。開かれた redirect_uri の C とフラグメントの内容を提示してきたブラウザのために検証し `LoginResult` を返す。メールボックスには触らない |
| `redirectUriFor(challenge)` | `${origin}${redirectPath}/${C}` |
| `pollResult(session)` | §8.1。メールボックスから `LoginResult` を 1 回だけ取り出す。無ければ `null` |

`receiveDirectPost` と `exchange` はどちらも成功時にチャレンジを使用済みにする (§9 手順 3)。同じチャレンジへの
2 回目以降の応答は、経路を問わず `AuthError('request_used', 400)`。検証に失敗した応答は使用済みにしない。

`LoginResult` は `{ status: 'ok', claims: IdTokenClaims } | { status: 'denied' }`。
セッションは `claims.sub` (CCID) に結び付けること (§9)。`name` / `picture` は Authenticator の自己申告で表示専用 (§7.3)。

### `AuthStore`

```ts
interface AuthStore {
    get(key: string): Promise<string | null>
    set(key: string, value: string, ttlSeconds: number): Promise<void>
    delete(key: string): Promise<void>
}
```

`MemoryStore` (単一プロセス用の参照実装) を同梱している。テストやローカル開発向け。

### その他

- `authorizationRequestUri(requestUri, mode)` — `https://<host>/<path>` を `concrnt-auth://<mode>/<host>/<path>` にする (§5.2)。ブラウザ側で使う
- `parseAuthorizationResponse(FormData | URLSearchParams)` — form / フラグメントから `{ id_token, error }` を取り出す (他は無視)
- `verifyIdToken(token, { origin, nonce, now?, clockSkew? })` — §9 手順 1〜6 の単体。ConcrntAuth を使わず検証だけしたいとき
- `emojihash(value)` — `display_code` の絵文字フィンガープリント (`@concrnt/worldlib` と同じ表・同じアルゴリズム)
- `AuthError { code, status }` — `invalid_option` / `invalid_request` / `request_used` / `missing_id_token` / `invalid_id_token`

## 中で何をしているか

RP が持つ状態は `secret` と `store` の 2 つだけ。

- **チャレンジ C** — QR に入るので JWT ではなくバイナリ詰め。36 バイトを base64url にした 48 文字:

  ```text
  C = base64url( exp(4B, uint32 BE) || sh(16B) || mac(16B) )
  sh  = SHA-256(session) の先頭 16 バイト
  mac = HMAC-SHA256(secret, 先頭 20 バイト) の先頭 16 バイト (定数時間比較で検証)
  ```

  `request_uri` のパス末尾と、Request Object の `redirect_uri` のパス末尾に載せる (`state` は使わない。応答がどの要求のものかは
  届いた URL で決まる)。`getRequestObject` は C を検証して Request Object を毎回組み立て直す。`nonce` は保存せず `base64url(HMAC(secret, "nonce:" + C))` で導出し、応答時に同じ計算で照合する。
  `sh` はブラウザ秘密 `session` のハッシュで、別端末フローの結果の宛先になる。`session` 自体は QR に載らないので、
  QR を見た第三者は結果を取れない (§8.1)。
- **応答方式はサーバーに現れない** — Authorization Request URI は `concrnt-auth://<mode>/<host>/<requestPath>/<C>`
  (100 バイト前後、QR バージョン 5〜6) で、`<mode>` を付けるのはブラウザ。Request Object は両方式で同一
  (`response_mode` 無し、`display_code` 常時)。Authenticator は URI の `<mode>` に従って配送し、direct_post のときだけ
  `display_code` と別端末警告を出す
- **受け口の役割が固定** — `redirect_uri` への POST (direct_post) は「開始した人のために預かる」。`exchange` (fragment) は
  「提示した人をログインさせる」。どちらが来たかを判定したり、開始ブラウザとの一致を照合したりしない。
  他人に fragment のリンクを踏ませても、その人が自分のアカウントでログインするだけで、リンクを作った側には何も届かない (§10.1)
- **メールボックス** — キー `concrnt-auth:mailbox:<base64url(sh)>`、値は HS256 JWT (`typ: concrnt-auth-result+jwt`、
  `{ sh, exp, result }`)。`pollResult` は署名と宛先 `sh` を照合してから返すので、ストアが改ざんされても
  別の箱の中身を移されてもログインには至らない
- **一回限り** (§9 手順 3) — 正当な応答を受理したら `concrnt-auth:used:<C>` を C の `exp` まで記録し、以後は経路を問わず拒否する。
  `exchange` は提示者をログインさせるので、有効期間内の ID Token はその要求に対する bearer になる。これが無いと漏れた
  ID Token で 2 人目がログインできてしまう。ストアに原子性は要求しないので、同時到着した 2 つの応答が両方通る競合は残る
  (どちらも同じエンティティの正当な応答なので、2 つのブラウザがログインする以上のことは起きない)
- **`request_uri` は再取得できる** — §5.2 の一回限りは SHOULD。Request Object に QR 保持者が知らない情報は含まれないので、
  `exp` の短さで受け入れている

## 開発

```sh
pnpm install
pnpm build        # dist/
pnpm test         # vitest (テスト内に最小の Authenticator を持ち、§9 の各失敗系まで通す)
pnpm lint
```

### sample

`sample/` は Cloudflare Workers + React の RP 実装例 (`sample/README.md`)。ライブラリをビルドしてから動かす:

```sh
pnpm build
pnpm --filter auth-client-sample dev
```

## 今後の候補

- fetch ハンドラ層 (ルーティング + ログインセッションを込みにした `Request → Response`)
- ブラウザ側ヘルパー (開始・QR / リンク用 URI・ポーリング・フラグメントの転送)
- CIP-18 (Service Key Certificate)
