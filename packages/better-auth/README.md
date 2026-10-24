# @concrnt/better-auth

[CIP-17: External Service Authentication (Sign-In with Concrnt)](https://github.com/concrnt/CIPs) を
[better-auth](https://www.better-auth.com) のプラグインにしたもの。`plugins: [concrnt()]` を足すだけで、
Concrnt のアプリ (Authenticator) で承認してログインできるようになる。

Concrnt の ID Token は「外部で署名された ID Token」なので、better-auth が OAuth / Google One Tap で使っている
サインイン処理 (`handleOAuthUserInfo`) にそのまま渡す。CCID は better-auth 標準の `account` テーブルに
`providerId: 'concrnt'` / `accountId: <CCID>` として入り、**専用テーブルもマイグレーションも要らない**。
1 ユーザーに CCID は 1 つで、既存ユーザーへの CCID の追加は提供しない。ログイン中の CCID は組み込みの `listAccounts` で読める。

- 未登録の CCID はそのままサインアップになる。`signUp: 'confirm'` で「作りますか?」を挟め、`'disabled'` で既存ユーザーに限定できる
- 状態は better-auth の `verification` テーブルの行だけ。要求ごとに 1 行を置き、受理時に原子的に消費する
  (CIP-17 §9 手順 3 の nonce 一回限り)。追加のストアや secret は要らない
- プロトコルの状態機械 (要求の発行・Request Object・応答の受理・一回限り)、着地ページ、ブラウザ側の待ち合わせは
  [`@concrnt/auth-client`](../auth-client/README.md) のもの。このプラグインは verification テーブルを `AuthStore` に写し、
  検証済みのクレームを better-auth のユーザー/セッションに結び付ける部分だけを持つ

## 導入

```sh
npm i @concrnt/better-auth
```

```ts
// auth.ts (サーバー)
import { betterAuth } from 'better-auth'
import { concrnt } from '@concrnt/better-auth'

export const auth = betterAuth({
    // ...
    plugins: [concrnt()]
})
```

```ts
// auth-client.ts (ブラウザ)
import { createAuthClient } from 'better-auth/react'
import { concrntClient } from '@concrnt/better-auth/client'

export const authClient = createAuthClient({ plugins: [concrntClient()] })
```

RP のオリジン (CIP-17 §5.1) は better-auth の `baseURL` のオリジンになる。Authorization Request URI には host しか載らず
https が暗黙なので、ローカル開発では https のトンネル等を `baseURL` にする (http では Authenticator から到達できない)。

better-auth の `user` には `email` が必須なので、Concrnt だけで作られたユーザーには到達不能なプレースホルダー
(`<CCID>@concrnt.placeholder.invalid`、SIWE プラグインと同じ方式) が入る。`name` / `image` は ID Token の
`name` / `picture` (Authenticator の自己申告、CIP-17 §7.3) から取る。

## 使い方 (ブラウザ)

応答方式 (CIP-17 §8) を選ぶのはブラウザ側で、サーバーは関知しない。1 つの要求から QR 用 (`direct_post`) と
同一端末リンク用 (`fragment`) の両方の URI が返るので、両方出しておけば先に応答が返った方でログインが成立する。

```ts
const { data, error } = await authClient.signIn.concrnt({
    callbackURL: '/',
    newUserCallbackURL: '/welcome', // 省略可。初めての CCID でユーザーが作られたときの戻り先 (OAuth と同じ)
    onChallenge: ({ directPostUri, fragmentUri, displayCode, exp }) => {
        renderQr(directPostUri)        // 別端末: Authenticator が読む QR
        show(displayCode)              // 同意画面と見比べる絵文字 (§6)
        location.href = fragmentUri    // 同一端末: アプリがあればこれで開く (ユーザー操作の直後に)
    }
})
// data.status: 'ok' | 'signup_required' | 'denied' | 'expired' | 'aborted'。ok なら cookie が入っていて useSession が更新される。
// data.isNewUser はこのログインでユーザーが作られたかどうか

// ログイン中の CCID (better-auth 組み込み)
const { data: accounts } = await authClient.listAccounts() // providerId === 'concrnt' の行の accountId が CCID
```

- 別端末 (§8.1): クライアントが `status` をポーリングし、結果が届けばそのブラウザにセッションが入る
- 同一端末 (§8.2): Authenticator が `redirect_uri#id_token=…` を開く。その URL (`/api/auth/concrnt/callback/<C>`) には
  プラグインが小さな着地ページを返し、フラグメントを `exchange` に送ってから `callbackURL` へ遷移する。
  アプリ側に実装は要らない。拒否や失敗のときは `callbackURL?error=<code>` に戻る

`onChallenge` の他に `pollIntervalMs` (既定 2000)、`signal` (中断)、`fetchOptions` を渡せる。

### 作る前に確認する (`signUp: 'confirm'`)

未登録の CCID のとき、サーバーはユーザーを作らずに検証済みの内容を 10 分だけ保留し (verification テーブル + 署名付き HttpOnly cookie)、
`{ status: 'signup_required', profile: { ccid, name, picture } }` を返す。再承認は要らない。

```ts
const { data } = await authClient.signIn.concrnt({ onChallenge })
if (data?.status === 'signup_required') showConfirm(data.profile)
// 同一端末フローでは着地ページから callbackURL に戻ってくるので、ページ読み込み時に保留を見る
const { data: held } = await authClient.concrnt.pendingSignUp() // { profile } | { profile: null }

await authClient.concrnt.signUp() // 「作って続行」: 保留を消費してユーザーを作り、セッションを発行する (1 回限り)
await authClient.signIn.concrnt({ onChallenge }) // 「別のアカウントを使用」: 新しいログインを始めれば保留は捨てられる
```

## オプション

```ts
concrnt({
    clientMetadata?: ClientMetadata // §5.3 client_metadata。既定 { client_name: appName }
    signUp?: 'auto' | 'confirm' | 'disabled' // 未登録の CCID の扱い。既定 'auto' (即作成)。'confirm' は確認後に作る、'disabled' は拒否 (SIGNUP_DISABLED)
    requestTtl?: number             // Request Object の有効期間 (秒)。既定 300
    landing?: Partial<{ title; working; denied; back }> // fragment 着地ページの文言
})
```

## endpoint (basePath 配下)

| Method / Path | 役割 |
|---|---|
| `POST /concrnt/start` `{ callbackURL?, newUserCallbackURL? }` | 要求を発行。`{ directPostUri, fragmentUri, displayCode, exp, pollToken }`。新規ユーザーは `newUserCallbackURL` (あれば) に戻る |
| `GET /concrnt/request/:C` | §5.3 Request Object (Authenticator が取る)。`Access-Control-Allow-Origin: *` |
| `POST /concrnt/callback/:C` | §8.1 direct_post の受け口。`application/x-www-form-urlencoded` の `id_token` / `error`。検証して結果を預け 204。**送信者にセッションは発行しない** |
| `GET /concrnt/callback/:C` | §8.2 fragment の着地ページ (HTML) |
| `POST /concrnt/exchange/:C` `{ id_token?, error? }` | §8.2 提示したブラウザをサインインさせてセッションを発行 |
| `POST /concrnt/status` `{ pollToken }` | §8.1 開始したブラウザが結果を回収。`pending` / `denied` / `ok` / `signup_required` |
| `GET /concrnt/pending-sign-up` | `signUp: 'confirm'`: このブラウザに保留中の `{ profile }` (無ければ `null`) |
| `POST /concrnt/sign-up` | `signUp: 'confirm'`: 保留を消費してユーザーを作り、セッションを発行 (1 回限り) |

`ok` の応答は `{ status, callbackURL, isNewUser, token, user }`。`callbackURL` / `newUserCallbackURL` は better-auth の `trustedOrigins` で検証される。

## 完了時の判定

検証済みの CCID をどう扱うかは、better-auth の OAuth サインインと同じ (`handleOAuthUserInfo`):

| 状況 | 結果 |
|---|---|
| `account` に `concrnt` / CCID の行がある | そのユーザーとしてサインイン (提示したブラウザが別のユーザーでログイン中でも切り替わる) |
| 行が無い | ユーザーを作成して行を追加。提示したブラウザが別のユーザーでログイン中でも、そのユーザーには付けず新しいユーザーになる (1 ユーザーに CCID は 1 つ)。`signUp: 'confirm'` なら作らずに `signup_required` を返し、`POST /concrnt/sign-up` で作る。`'disabled'` なら `SIGNUP_DISABLED` |

`user.create` / `account.create` の databaseHooks や `account.updateAccountOnSignIn` など、better-auth のフックと設定はそのまま効く。
`account.idToken` には直近の ID Token が入るので、`concrnt_domain` などの自己申告クレームが必要ならそこから読める。

## 安全性のメモ

- **受け口の役割は固定** (CIP-17 §8): `callback` への POST は預けるだけで、`exchange` は提示したブラウザをログインさせる。
  他人に fragment リンクを踏ませても、その人が自分でログインするだけで開始した側には何も届かない
- **一回限り** (§9 手順 3): 要求の行を `consumeVerificationValue` で原子的に消費するので、同じ要求への同時応答は 1 件しか通らず、
  QR とリンクのどちらで成立してももう一方は使えない。検証に失敗した応答は消費しない
- **既存ユーザーへの紐付けをしない**: 他人の ID Token を含む fragment リンクをログイン中のユーザーに踏ませても、
  そのユーザーに CCID が付くことはない (そのブラウザが ID Token の CCID のユーザーとしてログインし直すだけ)
- **status は POST + JSON**: GET にすると cross-site のトップレベル遷移でセッション cookie が設定できてしまう (login CSRF)。
  POST + JSON なら better-auth の CSRF モデル (JSON 限定 + cookie 同伴時の Origin 検証) に乗る
- 着地ページのスクリプトは固定文字列で、`Content-Security-Policy: script-src 'sha256-…'` を付けて返す

## エラーコード (`$ERROR_CODES`)

`CHALLENGE_NOT_FOUND` (404) · `CHALLENGE_ALREADY_USED` · `MISSING_ID_TOKEN` · `INVALID_ID_TOKEN` · `SIGNUP_DISABLED` (403) ·
`NO_PENDING_SIGNUP` · `UNABLE_TO_SIGN_IN` (401)

## サンプル

[`samples/better-auth`](../../samples/better-auth/README.md) — Cloudflare Workers + D1 + React。
