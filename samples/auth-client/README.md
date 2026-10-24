# auth-client-sample

[CIP-17: External Service Authentication (Sign-In with Concrnt)](https://github.com/concrnt/CIPs) の
RP (Relying Party) 側の最小サンプル。プロトコル処理は [`@concrnt/auth-client`](../../packages/auth-client/README.md) に任せ、
RP が自分で書く部分 (ルーティング・ログイン後のセッション・画面) だけがここにある。

Cloudflare Workers (バックエンド・D1) + React (フロント)。ライブラリの `AuthStore` は D1 で実装している (`worker/store.ts`)。
状態は D1 だけで、KV も secret も要らない。

## 流れと対応するコード

ログインボタンは 1 つで、押すと 1 往復で要求を作る。応答方式 (同一端末用 `fragment` / 別端末用 `direct_post`) を
選ぶのはブラウザ側で、`start` が返す 2 つの URI を両方使う。`concrnt-auth://fragment/…` にすぐ遷移して同じ端末に
Concrnt アプリがあればそれが開き (同一端末)、開かなかった場合に備えて画面には `concrnt-auth://direct_post/…` の QR も出す (別端末)。
先に応答が返った方でログインが成立する。Worker はどちらが使われたかを知らない。

```
  ブラウザ (src/App.tsx)          Worker (worker/index.ts)                       Authenticator (world-app)
  ----------------------          ------------------------                       -------------------------
  1. ボタン押下 (runLogin) -----> POST /api/login/start  → auth.start() をそのまま返す
                                  要求の行を D1 に置く。pollToken はブラウザだけが知る
  2. onChallenge で QR を描き、リンクに遷移

  --- 別端末 (§8.1 direct_post) — QR ---
                                                                          --->  3. QR を読み request_uri を GET
                                  GET /auth/request/:C   → auth.getRequestObject(C)
                                                                                4. RP の host と display_code を表示して同意を取る
                                                                                5. master key で ID Token に署名
                                  POST /auth/callback/<C> <-------------------- 6. id_token を redirect_uri (要求ごと) に direct_post
                                  auth.receiveDirectPost(C) → 検証して要求を消費し、結果を預ける → 204 (送信者には何も発行しない)
  7. POST /api/login/status ---> auth.pollResult(pollToken) → D1 にセッションを作り cookie sid で発行
     { pollToken }               (runLogin が 2 秒ごとに繰り返す)
     ログイン表示

  --- 同一端末 (§8.2 fragment) — リンク ---
  2'. 遷移 ---------(OS の URL スキーム)---------------------------------------->  3'. request_uri を GET、同意、署名
                                                                                4'. redirect_uri#id_token=… を
                                                                                    ブラウザで開く
  5'. GET /auth/callback/<C>  → ライブラリの着地ページ (landingPage)。フラグメントを読んで
      POST /api/login/exchange/<C> { id_token } → auth.exchange(C) → 検証して、このブラウザに cookie を発行
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

ただし Authorization Request URI には host しか載らず `request_uri` は https が暗黙なので (§5.2)、
`http://localhost` のままでは Authenticator から到達できない。実際に world-app から QR を読んで試すには公開 https URL が必要:

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

- **CORS**: world-app の Authenticator は webview の `fetch` で `request_uri` を GET し `redirect_uri` に POST する。
  どちらも `Access-Control-Allow-Origin: *` を返さないとブラウザ系 Authenticator からは成功しない (ライブラリは HTTP を
  扱わないので RP 側で付ける)。
- **セッションを発行するのは JSON の POST だけ**: `/api/login/status` と `/api/login/exchange/<C>` は `Content-Type: application/json`
  以外を 415 で弾く。form を受けると cross-site の `<form>` で他人の ID Token を踏まされてその人としてログインしてしまう (login CSRF)。
  GET も同じ理由で無い。
- **ログイン結果の取得はブラウザ秘密で**: `pollToken` は `/api/login/start` の応答にだけ入り、QR には載らない。
- **受け口は役割で分ける**: `/auth/callback/<C>` (= `redirect_uri`) への POST は Authenticator からの direct_post を預かるだけで、送信者には
  cookie を発行しない。`/api/login/exchange/<C>` はフラグメントを持ってきたブラウザをログインさせる。開始したブラウザかどうかは見ない。
  どの要求への応答かは URL の `<C>` で決まる (`state` は無い)。
- **着地ページは Worker が返す**: `assets.run_worker_first` に `/auth/*` と `/api/*` を入れてある。無いと compatibility_date が
  2025-04-01 以降では navigation GET が Worker を通らず SPA の `index.html` になる。
- **Authorization Request URI** は `concrnt-auth://direct_post/<host>/auth/request/<C>` で 80〜90 バイト (host 次第)。

## 対象外

- CIP-18 (Service Key Certificate)
