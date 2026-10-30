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
     authClient.signIn.concrnt   -----> POST /api/auth/concrnt/start
                                         要求の行を verification テーブルに作り、QR 用とリンク用の URI を返す
  2. onChallenge で QR (post) を描き、同一端末リンク (fragment) へ遷移

  --- 別端末 (§8.1 post) — QR ---
                                                                              --->  3. QR (concrnt-auth://post/<host>/api/auth/concrnt/callback?n=…) を読む
                                                                                    4. RP の host と display_code (= emojihash(n)) を表示して同意を取る
                                                                                    5. master key で ID Token に署名 (aud = 送り先 URL)
                                         POST /api/auth/concrnt/callback?n=… <----- 6. id_token を送り先 URL (クエリ込み) に POST
                                         id_token の nonce で要求を引き、検証し、行を消費して結果を預ける → 204 (送信者には何も発行しない)
  7. (クライアントが自動で) POST /api/auth/concrnt/status { pollToken }
                                         結果を取り出し、account (providerId 'concrnt') からユーザーを引いてセッション cookie を発行
     useSession が更新されてログイン表示
     未登録の CCID なら signup_required (ユーザーは未作成、保留の cookie だけ) → 「アカウントを作りますか?」
  8. 「作って続行」 ------------------> POST /api/auth/concrnt/sign-up   保留を消費してユーザーを作り、セッション cookie を発行
     「別のアカウントを使用」→ 1. へ (新しい start で保留は捨てられる)

  --- 同一端末 (§8.2 fragment) — リンク ---
  2'. 遷移 ---------(OS の URL スキーム)----------------------------------------->  3'. URI を読み、同意、署名
                                                                                    4'. 送り先 URL#id_token=… をブラウザで開く
  5'. GET /api/auth/concrnt/callback?n=…  → プラグインの着地ページ (HTML)
      着地ページが POST /api/auth/concrnt/exchange → このブラウザにセッション cookie → callbackURL (/) へ
      (未登録の CCID なら保留の cookie だけ付けて / へ。ページが GET /api/auth/concrnt/pending-sign-up で気付いて確認画面を出す)
  6'. ログイン表示 (作成したときは newUserCallbackURL (/?welcome=1) に戻り、案内を出す)
```

- `worker/auth.ts` — `betterAuth({ database: D1, plugins: [concrnt({ signUp: 'confirm' })] })`。未登録の CCID は確認してから作る
- `worker/index.ts` — `/api/auth/*` を `auth.handler` に渡すだけ
- `src/auth-client.ts` — `createAuthClient({ plugins: [concrntClient()] })`
- `src/App.tsx` — ログイン (QR・照合コード・同一端末リンク・待機)、「アカウントを作りますか?」(`signup_required` / `pendingSignUp` → `signUp`)、新規ユーザーの案内 (`isNewUser` / `?welcome=1`)、`useSession`、この CCID の表示 (`listAccounts`)、サインアウト。1 ユーザーに CCID は 1 つで、追加・解除の UI は無い
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

PR の Preview (Workers Builds) は `wrangler.jsonc` の `previews` の D1 を使う。作り直すときは `wrangler d1 create auth-client-better-auth-sample-preview` で
`preview_database_id` と `previews.d1_databases[].database_id` を差し替え、`pnpm migrate:preview` でスキーマを入れる。
`BETTER_AUTH_SECRET` は Preview 側にも要る: `openssl rand -base64 32 | wrangler preview base-config secret put BETTER_AUTH_SECRET`。

送り先 URL (CIP-17 §5.1・ID Token の aud) は `<オリジン>/api/auth/concrnt/callback?n=…` で、オリジンはリクエストのオリジン
(`PUBLIC_ORIGIN` が空のとき) なので、公開 URL は 1 つに定めること (`workers_dev: false` にしてある)。

## メモ

- ログインボタンは 1 つ。CCID が登録済みかどうかはログイン前に分からないので、未登録だったときに「作りますか?」を聞く
  (`signUp: 'confirm'`)。Authenticator での承認は 1 回で済み、保留は 10 分で失効する。
  作られたことは別端末フローなら結果の `isNewUser`、同一端末フローなら `newUserCallbackURL` への戻りで分かり、画面に案内を出す
- ローカル D1 は `database_id` ごとに別ファイル (`.wrangler/state/`) なので、id を差し替えたら `pnpm migrate:local` をやり直す
- better-auth の `user` には `email` が必須。Concrnt にメールは無いのでプラグインが `<CCID>@concrnt.placeholder.invalid` を入れる
- `useSession()` は再取得のたびに未ログインだと `isPending` が立つ (`isRefetching` も同時に true)。待機画面を 3 秒ごとに
  再取得しているので、ローディング表示は `isPending && !isRefetching` で初回だけに限っている
- Authorization Request URI は `concrnt-auth://post/<host>/api/auth/concrnt/callback?n=<nonce>` で約 80〜95 バイト (host 次第)
- Cloudflare Web Analytics の自動注入 (beacon.min.js) は、fragment の着地ページでは CSP (`script-src 'sha256-…'`) に弾かれて
  コンソールにエラーが出る。着地ページは一瞬で `callbackURL` へ遷移する中継なので動作に影響はない
