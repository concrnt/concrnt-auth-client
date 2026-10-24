# @concrnt/better-auth

[CIP-17: External Service Authentication (Sign-In with Concrnt)](https://github.com/concrnt/CIPs) を
[better-auth](https://www.better-auth.com) のプラグインにしたもの。`plugins: [concrnt()]` を足すだけで、
Concrnt のアプリ (Authenticator) で承認してログインできるようになる。

Concrnt の ID Token は「外部で署名された ID Token」なので、better-auth が OAuth / Google One Tap で使っている
サインイン処理 (`handleOAuthUserInfo`) にそのまま渡す。CCID は better-auth 標準の `account` テーブルに
`providerId: 'concrnt'` / `accountId: <CCID>` として入り、**専用テーブルもマイグレーションも要らない**。
一覧・解除は better-auth 組み込みの `listAccounts` / `unlinkAccount` で行う。

- 未登録の CCID はそのままサインアップになる (`disableSignUp: true` で既存ユーザーに限定できる)
- ログイン中のユーザーへの CCID の追加は `link: true` (クライアントの `authClient.concrnt.link()`)
- 状態は better-auth の `verification` テーブルの行だけ。要求ごとに 1 行を置き、受理時に原子的に消費する
  (CIP-17 §9 手順 3 の nonce 一回限り)。追加のストアや secret は要らない
- プロトコルの純粋な部分 (ID Token の検証、Authorization Request URI、display_code) は
  [`@concrnt/auth-client`](../auth-client/README.md) を使う

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
// data.status: 'ok' | 'denied' | 'expired' | 'aborted'。ok なら cookie が入っていて useSession が更新される。
// data.isNewUser はこのログインでユーザーが作られたかどうか

// ログイン中のユーザーに CCID を追加
await authClient.concrnt.link({ onChallenge })

// 一覧・解除は better-auth 組み込み
const { data: accounts } = await authClient.listAccounts() // providerId === 'concrnt' の行が CCID
await authClient.unlinkAccount({ accountId: account.id })  // 最後のアカウントは解除できない (ログイン不能を防ぐ)
```

- 別端末 (§8.1): クライアントが `status` をポーリングし、結果が届けばそのブラウザにセッションが入る
- 同一端末 (§8.2): Authenticator が `redirect_uri#id_token=…` を開く。その URL (`/api/auth/concrnt/callback/<C>`) には
  プラグインが小さな着地ページを返し、フラグメントを `exchange` に送ってから `callbackURL` へ遷移する。
  アプリ側に実装は要らない。拒否や失敗のときは `callbackURL?error=<code>` に戻る

`onChallenge` の他に `pollIntervalMs` (既定 2000)、`signal` (中断)、`fetchOptions` を渡せる。

## オプション

```ts
concrnt({
    clientMetadata?: ClientMetadata // §5.3 client_metadata。既定 { client_name: appName }
    disableSignUp?: boolean         // 未登録の CCID を拒否する (SIGNUP_DISABLED)。既定 false
    requestTtl?: number             // Request Object の有効期間 (秒)。既定 300
    landing?: Partial<{ title; working; denied; back }> // fragment 着地ページの文言
})
```

## endpoint (basePath 配下)

| Method / Path | 役割 |
|---|---|
| `POST /concrnt/start` `{ callbackURL?, newUserCallbackURL?, link? }` | 要求を発行。`{ directPostUri, fragmentUri, displayCode, exp, pollToken }`。新規ユーザーは `newUserCallbackURL` (あれば) に戻る。`link: true` はセッション必須で、検証した CCID をそのユーザーに紐付ける |
| `GET /concrnt/request/:C` | §5.3 Request Object (Authenticator が取る)。`Access-Control-Allow-Origin: *` |
| `POST /concrnt/callback/:C` | §8.1 direct_post の受け口。`application/x-www-form-urlencoded` の `id_token` / `error`。検証して結果を預け 204。**送信者にセッションは発行しない** |
| `GET /concrnt/callback/:C` | §8.2 fragment の着地ページ (HTML) |
| `POST /concrnt/exchange/:C` `{ id_token?, error? }` | §8.2 提示したブラウザをサインイン/紐付けしてセッションを発行 |
| `POST /concrnt/status` `{ pollToken }` | §8.1 開始したブラウザが結果を回収。`pending` / `denied` / `ok` |

`ok` の応答は `{ status, callbackURL, isNewUser, token, user }`。`callbackURL` / `newUserCallbackURL` は better-auth の `trustedOrigins` で検証される。

## 完了時の判定

検証済みの CCID をどう扱うかは、better-auth の OAuth サインインと同じ (`handleOAuthUserInfo`):

| 状況 | 結果 |
|---|---|
| `account` に `concrnt` / CCID の行がある | そのユーザーとしてサインイン (提示したブラウザが別のユーザーでログイン中でも切り替わる) |
| 行が無く、通常のサインイン | ユーザーを作成して行を追加 (`disableSignUp` なら `SIGNUP_DISABLED`) |
| 行が無く、`link: true` | 開始したユーザーに行を追加。開始したセッションを持つブラウザでしか完了できない (`LINK_SESSION_MISMATCH`) |
| 行が別のユーザーのもので、`link: true` | 409 (`account_ownership_conflict`) |

`user.create` / `account.create` の databaseHooks や `account.updateAccountOnSignIn` など、better-auth のフックと設定はそのまま効く。
`account.idToken` には直近の ID Token が入るので、`concrnt_domain` などの自己申告クレームが必要ならそこから読める。

## 安全性のメモ

- **受け口の役割は固定** (CIP-17 §8): `callback` への POST は預けるだけで、`exchange` は提示したブラウザをログインさせる。
  他人に fragment リンクを踏ませても、その人が自分でログインするだけで開始した側には何も届かない
- **一回限り** (§9 手順 3): 要求の行を `consumeVerificationValue` で原子的に消費するので、同じ要求への同時応答は 1 件しか通らず、
  QR とリンクのどちらで成立してももう一方は使えない。検証に失敗した応答は消費しない
- **紐付けの束縛**: `link: true` の完了は、開始したセッションを持つブラウザだけに許す。他人の ID Token を含む fragment リンクを
  ログイン中のユーザーに踏ませても、その CCID が紐付くことはない
- **status は POST + JSON**: GET にすると cross-site のトップレベル遷移でセッション cookie が設定できてしまう (login CSRF)。
  POST + JSON なら better-auth の CSRF モデル (JSON 限定 + cookie 同伴時の Origin 検証) に乗る
- 着地ページのスクリプトは固定文字列で、`Content-Security-Policy: script-src 'sha256-…'` を付けて返す

## エラーコード (`$ERROR_CODES`)

`CHALLENGE_NOT_FOUND` (404) · `CHALLENGE_ALREADY_USED` · `MISSING_ID_TOKEN` · `INVALID_ID_TOKEN` · `SESSION_REQUIRED` (401) ·
`LINK_SESSION_MISMATCH` (401) · `SIGNUP_DISABLED` (403) · `UNABLE_TO_SIGN_IN` (401)

## サンプル

[`samples/better-auth`](../../samples/better-auth/README.md) — Cloudflare Workers + D1 + React。
