# auth-client-sample

[CIP-17: External Service Authentication (Sign-In with Concrnt)](https://github.com/concrnt/CIPs) の
RP (Relying Party) 側の最小サンプル。プロトコル処理は [`@concrnt/auth-client`](../README.md) に任せ、
RP が自分で書く部分 (ルーティング・cookie・ログイン後のセッション・画面) だけがここにある。

Cloudflare Workers (バックエンド) + React (フロント)。ライブラリの `AuthStore` は Workers KV で実装している (`worker/store.ts`)。

## 流れと対応するコード

ログインボタンは 1 つで、押すと 1 往復でチャレンジを作る。応答方式 (同一端末用 `fragment` / 別端末用 `direct_post`) を
選ぶのはブラウザ側で、同じ `requestUri` から 2 つの URI を組む。`concrnt-auth://fragment/…` にすぐ遷移して同じ端末に
Concrnt アプリがあればそれが開き (同一端末)、開かなかった場合に備えて画面には `concrnt-auth://direct_post/…` の QR も出す (別端末)。
先に応答が返った方でログインが成立する。Worker はどちらが使われたかを知らない。

```
  ブラウザ (src/App.tsx)          Worker (worker/index.ts)                       Authenticator (world-app)
  ----------------------          ------------------------                       -------------------------
  1. ボタン押下 ----------------> POST /api/login/start  → auth.start() をそのまま返す
                                  session とチャレンジ C。何も保存しない
  2. requestUri から URI を組み、リンクに遷移 + QR 表示

  --- 別端末 (§8.1 direct_post) — QR ---
                                                                          --->  3. QR を読み request_uri を GET
                                  GET /auth/request/:C   → auth.getRequestObject(C)
                                                                                4. RP の host と display_code を表示して同意を取る
                                                                                5. master key で ID Token に署名
                                  POST /auth/callback/<C> <-------------------- 6. id_token を redirect_uri (要求ごと) に direct_post
                                  auth.receiveDirectPost(C) → 検証して mailbox に預ける → 204 (送信者には何も発行しない)
  7. GET /api/login/status ----> auth.pollResult(session) → ログイントークン L を cookie sid で発行
     ログイン表示

  --- 同一端末 (§8.2 fragment) — リンク ---
  2'. 遷移 ---------(OS の URL スキーム)---------------------------------------->  3'. request_uri を GET、同意、署名
                                                                                4'. redirect_uri#id_token=… を
                                                                                    ブラウザで開く
  5'. /auth/callback/<C>#… で起動、
      フラグメントを読んで -----> POST /api/login/session/<C> (フラグメントの内容そのまま)
      URL から消す               auth.exchange(C) → 検証して、このブラウザに L を cookie で発行
  6'. ログイン表示
```

- `worker/index.ts` — ルーティング。`ConcrntAuth` を作って各エンドポイントで呼ぶだけ。`AuthError` はそのまま HTTP ステータスに写す
- `worker/store.ts` — Workers KV を `AuthStore` にする 3 行のアダプタ (KV の TTL 下限 60 秒に合わせる)
- `worker/session.ts` — ログイン成立後のセッション。ログイントークン L (HS256 JWT、cookie `sid`) の発行と検証。
  CIP-17 の範囲外で RP 固有なのでライブラリには入っていない。`/api/me` は署名を見るだけで、サーバーは何も記録しない
- `src/App.tsx` — URI の組み立て、QR 表示とポーリング、`/auth/callback#…` の転送

RP が持つ状態は `LOGIN_SECRET` (HMAC 鍵。ライブラリのトークンと L の両方に使う) と `LOGIN_KV` (ライブラリのストア) だけ。
トークンの形やリプレイ耐性などプロトコル側の設計はライブラリ README の「中で何をしているか」を参照。

## 動かす

リポジトリのルートでライブラリをビルドしてから:

```sh
pnpm install
pnpm build                                  # ルート: @concrnt/auth-client を dist/ へ
pnpm --filter auth-client-sample dev      # http://localhost:5173
```

ただし Authorization Request URI には host しか載らず `request_uri` は https が暗黙なので (§5.2)、
`http://localhost` のままでは Authenticator から到達できない。実際に world-app から QR を読んで試すには公開 https URL が必要:

- **デプロイする**: `wrangler kv namespace create LOGIN_KV` で作った id を `wrangler.jsonc` の `kv_namespaces[0].id` に入れ、
  `routes[0].pattern` を自分のドメインにして、`wrangler secret put LOGIN_SECRET` で署名鍵 (例: `openssl rand -base64 32`) を登録し
  `pnpm run deploy`。デプロイ済みの例: <https://auth-client-sample.concrnt.net>
- **ローカルをトンネルで公開する**: `cloudflared tunnel --url http://localhost:5173` 等で得た https URL を
  `.dev.vars` の `PUBLIC_ORIGIN` に書く (`.dev.vars.example` 参照)。`LOGIN_SECRET` は `http://localhost` でだけ
  未設定でも固定の開発用鍵で動く。

## 実装上の注意

- **CORS**: world-app の Authenticator は webview の `fetch` で `request_uri` を GET し `redirect_uri` に POST する。
  どちらも `Access-Control-Allow-Origin: *` を返さないとブラウザ系 Authenticator からは成功しない (ライブラリは HTTP を
  扱わないので RP 側で付ける)。
- **ログイン結果の取得はブラウザ秘密で**: `session` は `/api/login/start` の応答にだけ入り、QR には載らない。
- **受け口は役割で分ける**: `/auth/callback/<C>` (= `redirect_uri`) は Authenticator からの direct_post を預かるだけで、送信者には
  cookie を発行しない。`/api/login/session/<C>` はフラグメントを持ってきたブラウザをログインさせる。開始したブラウザかどうかは見ない。
  どの要求への応答かは URL の `<C>` で決まる (`state` は無い)。
- **ログアウトはサーバー側で失効できない**: L は記録していないので cookie を消すだけ。失効が必要なら L の `exp` を短くするか、
  ここにだけ小さな失効リストを持つ。
- **fragment の受け口は SPA**: `GET /auth/callback/<C>` は静的アセットの SPA フォールバックで `index.html` が返り、
  フロントエンドがフラグメントを読む。フラグメントは HTTP リクエストに含まれないので ID Token がサーバーログに残らない (§8.2)。

## 対象外

- CIP-18 (Service Key Certificate)
