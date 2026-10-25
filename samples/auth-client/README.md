# auth-client-sample

[CIP-17: External Service Authentication (Sign-In with Concrnt)](https://github.com/concrnt/CIPs) の
RP (Relying Party) 側の最小サンプル。プロトコル処理は [`@concrnt/auth-client`](../../packages/auth-client/README.md) に任せ、
RP が自分で書く部分 (ルーティング・ログイン後のセッション・画面) だけがここにある。

Cloudflare Workers (バックエンド・D1) + React (フロント)。ライブラリの `AuthStore` は D1 で実装している (`worker/store.ts`)。
状態は D1 だけで、KV も secret も要らない。

## 流れと対応するコード

ログインボタンは 1 つで、押すと 1 往復で要求を作る。応答方式 (同一端末用 `fragment` / 別端末用 `post`) を
選ぶのはブラウザ側で、`start` が返す 2 つの URI を両方使う。`concrnt-auth://fragment/…` にすぐ遷移して同じ端末に
Concrnt アプリがあればそれが開き (同一端末)、開かなかった場合に備えて画面には `concrnt-auth://post/…` の QR も出す (別端末)。
先に応答が返った方でログインが成立する。Worker はどちらが使われたかを知らない。要求の内容はすべて URI に載っていて (by-value)、
Authenticator が Worker に何かを取りに来ることは無い。

```
  ブラウザ (src/App.tsx)          Worker (worker/index.ts)                       Authenticator (world-app)
  ----------------------          ------------------------                       -------------------------
  1. ボタン押下 (runLogin) -----> POST /api/login/start  → auth.start() をそのまま返す
                                  要求の行を D1 に置く。pollToken はブラウザだけが知る
  2. onChallenge で QR を描き、リンクに遷移

  --- 別端末 (§8.1 post) — QR ---
                                                                          --->  3. QR (concrnt-auth://post/<host>/auth/callback?n=…) を読む
                                                                                4. RP の host と display_code (= emojihash(n)) を表示して同意を取る
                                                                                5. master key で ID Token に署名 (aud = https://<host>/auth/callback)
                                  POST /auth/callback?n=… <--------------------- 6. id_token を送り先 URL (クエリ込み) に POST
                                  auth.receivePost() → id_token の nonce で要求を引き、検証して消費し、結果を預ける → 204 (送信者には何も発行しない)
  7. POST /api/login/status ---> auth.pollResult(pollToken) → D1 にセッションを作り cookie sid で発行
     { pollToken }               (runLogin が 2 秒ごとに繰り返す)
     ログイン表示

  --- 同一端末 (§8.2 fragment) — リンク ---
  2'. 遷移 ---------(OS の URL スキーム)---------------------------------------->  3'. URI を読み、同意、署名
                                                                                4'. https://<host>/auth/callback?n=…#id_token=… を
                                                                                    ブラウザで開く
  5'. GET /auth/callback?n=…  → ライブラリの着地ページ (landingPage)。フラグメントを読んで
      POST /api/login/exchange { id_token } → auth.exchange() → 検証して、このブラウザに cookie を発行
      → / へ遷移
  6'. ログイン表示
```

- `worker/index.ts` — ルーティング。`ConcrntAuth` を作って各エンドポイントで呼ぶだけ。`AuthError` はそのまま HTTP ステータスに写す
- `worker/store.ts` — D1 を `AuthStore` にするアダプタ。`consume` は `DELETE … RETURNING` で原子的
- `worker/session.ts` — ログイン成立後のセッション。ランダムトークンを cookie `sid` に、行を D1 に。ログアウトで行を消す
  (CIP-17 の範囲外で RP 固有なのでライブラリには入っていない)
- `src/App.tsx` — 画面だけ。流れは `@concrnt/auth-client/browser` の `runLogin` に fetch を 2 つ渡す
- `migrations/0001_init.sql` — `login_store` (ライブラリの行) と `login_session`

## 動かす

リポジトリのルートでライブラリをビルドしてから:

```sh
pnpm install
pnpm build                                        # ルート: packages/* を dist/ へ
pnpm --filter auth-client-sample migrate:local    # ローカル D1 にスキーマを適用 (初回)
pnpm --filter auth-client-sample dev              # http://localhost:5173
```

ただし Authorization Request URI にはスキームを外した残りしか載らず送り先は https が暗黙なので (§5.2)、
`http://localhost` のままでは別端末の Authenticator から到達できない。実際に world-app から QR を読んで試すには公開 https URL が必要:

- **デプロイする**:
  ```sh
  wrangler d1 create auth-client-sample   # wrangler.jsonc の database_id を差し替える
  pnpm migrate:remote                     # リモート D1 にスキーマを適用
  pnpm run deploy                         # wrangler.jsonc の routes (custom_domain) を自分のドメインに変えてから
  ```
  デプロイ済みの例: <https://auth-client-sample.concrnt.net>
- **ローカルをトンネルで公開する**: `cloudflared tunnel --url http://localhost:5173` 等で得た https URL を
  `.dev.vars` の `PUBLIC_ORIGIN` に書く (`.dev.vars.example` 参照)。

## 実装上の注意

- **CORS**: world-app の Authenticator は webview の `fetch` で送り先 URL に POST する。
  `Access-Control-Allow-Origin: *` を返さないとブラウザ系 Authenticator からは成功しない (ライブラリは HTTP を
  扱わないので RP 側で付ける)。
- **セッションを発行するのは JSON の POST だけ**: `/api/login/status` と `/api/login/exchange` は `Content-Type: application/json`
  以外を 415 で弾く。form を受けると cross-site の `<form>` で他人の ID Token を踏まされてその人としてログインしてしまう (login CSRF)。
  GET も同じ理由で無い。
- **ログイン結果の取得はブラウザ秘密で**: `pollToken` は `/api/login/start` の応答にだけ入り、QR には載らない。
- **受け口は役割で分ける**: `/auth/callback` (= 送り先 URL) への POST は Authenticator からの応答を預かるだけで、送信者には
  cookie を発行しない。`/api/login/exchange` はフラグメントを持ってきたブラウザをログインさせる。開始したブラウザかどうかは見ない。
  どの要求への応答かは `id_token` の `nonce` (拒否なら `nonce` パラメータ) で決まる。コールバック URL は 1 本で要求ごとには変わらない。
- **着地ページは Worker が返す**: `assets.run_worker_first` に `/auth/*` と `/api/*` を入れてある。無いと compatibility_date が
  2025-04-01 以降では navigation GET が Worker を通らず SPA の `index.html` になる。
- **Authorization Request URI** は `concrnt-auth://post/<host>/auth/callback?n=<nonce>` で 70〜80 バイト (host 次第)。
  ID Token の `aud` は送り先 URL `https://<host>/auth/callback?n=<nonce>` そのもの (オリジンでもパスだけでもない)。
  RP 自身のクエリを送り先に持たせたければ `auth.start(undefined, { query: { return: '/settings' } })` (名前は 2 文字以上)。

## 対象外

- CIP-18 (Service Key Certificate)
