# auth-client-better-auth-sample

[CIP-17 (Sign-In with Concrnt)](https://github.com/concrnt/CIPs) を [better-auth](https://www.better-auth.com) で使う
RP (Relying Party) のサンプル。プロトコル処理もルーティングもセッションも [`@concrnt/better-auth`](../../packages/better-auth/README.md) と
better-auth に任せ、ここにあるのは better-auth の組み立て (`worker/auth.ts`、`plugins: [concrnt()]` だけ) と画面 (`src/App.tsx`) だけ。

Cloudflare Workers (バックエンド・D1) + React (フロント)。

## 流れと対応するコード

```
  ブラウザ (src/App.tsx)                 Worker: better-auth (/api/auth/*)                  Authenticator (world-app)
  ----------------------                 ---------------------------------                  -------------------------
  1. ボタン押下
     authClient.signIn.concrnt /  -----> POST /api/auth/concrnt/start
     authClient.concrnt.link             要求の行を verification テーブルに作り、QR 用とリンク用の URI を返す
  2. onChallenge で QR (direct_post) を描き、同一端末リンク (fragment) へ遷移

  --- 別端末 (§8.1 direct_post) — QR ---
                                                                              --->  3. QR を読み request_uri を GET
                                         GET /api/auth/concrnt/request/:C
                                                                                    4. RP の host と display_code を表示して同意を取る
                                                                                    5. master key で ID Token に署名
                                         POST /api/auth/concrnt/callback/:C <------ 6. id_token を direct_post
                                         検証し、要求の行を消費して結果を預ける → 204 (送信者には何も発行しない)
  7. (クライアントが自動で) POST /api/auth/concrnt/status { pollToken }
                                         結果を取り出し、account (providerId 'concrnt') からユーザーを引いて
                                         (無ければ作って) セッション cookie を発行
     useSession が更新されてログイン表示

  --- 同一端末 (§8.2 fragment) — リンク ---
  2'. 遷移 ---------(OS の URL スキーム)----------------------------------------->  3'. request_uri を GET、同意、署名
                                                                                    4'. redirect_uri#id_token=… をブラウザで開く
  5'. GET /api/auth/concrnt/callback/:C  → プラグインの着地ページ (HTML)
      着地ページが POST /api/auth/concrnt/exchange/:C → このブラウザにセッション cookie → callbackURL (/) へ
  6'. ログイン表示
```

- `worker/auth.ts` — `betterAuth({ database: D1, plugins: [concrnt()] })`。未登録の CCID はそのままサインアップになる
- `worker/index.ts` — `/api/auth/*` を `auth.handler` に渡すだけ
- `src/auth-client.ts` — `createAuthClient({ plugins: [concrntClient()] })`
- `src/App.tsx` — ログイン (QR・照合コード・同一端末リンク・待機)、`useSession`、紐付いた CCID の一覧 (`listAccounts`) と追加 (`concrnt.link`)・解除 (`unlinkAccount`)、サインアウト
- `migrations/0001_init.sql` — better-auth の標準テーブルだけ (user / session / account / verification)。プラグイン固有のテーブルは無い。`pnpm generate-migration` で `auth.cli.ts` から再生成

状態は D1 だけ。KV も別の secret も要らない。

## 動かす

リポジトリのルートでライブラリをビルドしてから:

```sh
pnpm install
pnpm build                                            # ルート: packages/* を dist/ へ
pnpm --filter auth-client-better-auth-sample migrate:local   # ローカル D1 にスキーマを適用 (初回)
pnpm --filter auth-client-better-auth-sample dev      # http://localhost:5173
```

Authenticator (Concrnt アプリ) から到達させるには https の公開 URL が要る。cloudflared 等でトンネルを張り、
`.dev.vars` に `PUBLIC_ORIGIN=https://…` を置く (`.dev.vars.example` 参照)。`BETTER_AUTH_SECRET` は localhost だけ未設定でも動く。

## デプロイ

```sh
wrangler d1 create auth-client-better-auth-sample      # wrangler.jsonc の database_id を差し替える
pnpm migrate:remote                                   # リモート D1 にスキーマを適用
pnpm run deploy                                       # wrangler.jsonc の routes (custom_domain) を自分のドメインに変えてから
openssl rand -base64 32 | wrangler secret put BETTER_AUTH_SECRET   # 初回デプロイ後 (secret が入るまで Worker は 500 を返す)
```

デプロイ済みの例: <https://better-auth-sample.concrnt.net>

RP のオリジン (CIP-17 §5.1) はリクエストのオリジン (`PUBLIC_ORIGIN` が空のとき) なので、公開 URL は 1 つに定めること
(`workers_dev: false` にしてある)。

## メモ

- ログインボタンは 1 つ。CCID が登録済みかどうかはログイン前に分からないが、未登録ならサインアップになるので分ける必要がない
- ローカル D1 は `database_id` ごとに別ファイル (`.wrangler/state/`) なので、id を差し替えたら `pnpm migrate:local` をやり直す
- better-auth の `user` には `email` が必須。Concrnt にメールは無いのでプラグインが `<CCID>@concrnt.placeholder.invalid` を入れる
- `useSession()` は再取得のたびに未ログインだと `isPending` が立つ (`isRefetching` も同時に true)。待機画面を 3 秒ごとに
  再取得しているので、ローディング表示は `isPending && !isRefetching` で初回だけに限っている
- Authorization Request URI は `concrnt-auth://direct_post/<host>/api/auth/concrnt/request/<C>` で約 90〜105 バイト (host 次第)
- Cloudflare Web Analytics の自動注入 (beacon.min.js) は、fragment の着地ページでは CSP (`script-src 'sha256-…'`) に弾かれて
  コンソールにエラーが出る。着地ページは一瞬で `callbackURL` へ遷移する中継なので動作に影響はない
