# @concrnt/better-auth

[CIP-17: External Service Authentication (Sign-In with Concrnt)](https://github.com/concrnt/CIPs) を
[better-auth](https://www.better-auth.com) のプラグインにしたもの。`plugins: [concrnt()]` を足すだけで、
Concrnt のアプリ (Authenticator) で承認してログインできるようになる。プロトコル処理は
[`@concrnt/auth-client`](../auth-client/README.md) に任せ、このパッケージは better-auth の endpoint・
ユーザー/セッション・verification テーブルに結び付ける部分だけを持つ。

形は公式のパスキープラグイン ([`@better-auth/passkey`](https://www.better-auth.com/docs/plugins/passkey)) に揃えてある:

- Concrnt の CCID はユーザーに紐付く「認証手段」で、専用テーブル `concrntIdentity` に入る (1 ユーザーに複数可)
- **authentication** (登録済みの CCID でログイン) と **registration** (ユーザーに CCID を追加) の 2 つの ceremony
- `registration.requireSession` (既定 `true`) / `resolveUser` / `afterVerification`、`authentication.afterVerification`
- 一覧・改名・解除の endpoint と、クライアント側の `useListIdentities()`

追加のストアや secret は要らない。チャレンジのメールボックスと使用済み記録は better-auth の verification テーブルに置き、
署名鍵は better-auth の `secret` を使う。

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

```sh
npx @better-auth/cli migrate   # concrntIdentity テーブルを追加 (または generate で SQL を出す)
```

```ts
// auth-client.ts (ブラウザ)
import { createAuthClient } from 'better-auth/react'
import { concrntClient } from '@concrnt/better-auth/client'

export const authClient = createAuthClient({ plugins: [concrntClient()] })
```

RP のオリジン (CIP-17 §5.1) は better-auth の `baseURL` のオリジンになる。Authorization Request URI には host しか載らず
https が暗黙なので、ローカル開発では https のトンネル等を `baseURL` にする (http では Authenticator から到達できない)。

## 使い方 (ブラウザ)

応答方式 (CIP-17 §8) を選ぶのはブラウザ側で、サーバーは関知しない。1 つの要求から QR 用 (`direct_post`) と
同一端末リンク用 (`fragment`) の両方の URI が返るので、両方出しておけば先に応答が返った方でログインが成立する。

```ts
// 別端末: QR を描き、応答が届くまで待つ
const { data, error } = await authClient.signIn.concrnt({
    mode: 'direct_post',
    callbackURL: '/',
    onChallenge: ({ directPostUri, fragmentUri, displayCode, exp }) => {
        renderQr(directPostUri)       // Authenticator が読む QR
        show(displayCode)             // 同意画面と見比べる絵文字 (§6)
        openAppLink.href = fragmentUri // 同じ端末にアプリがあればこれで開ける
    }
})
// data.status: 'ok' | 'denied' | 'expired' | 'aborted'。ok なら cookie が入っていて useSession が更新される

// 同一端末: アプリへ遷移する。戻りはサーバーの着地ページが処理して callbackURL へ戻る
await authClient.signIn.concrnt({ mode: 'fragment', callbackURL: '/' })

// ログイン中のユーザーに CCID を追加 (registration)
await authClient.concrnt.addIdentity({ mode: 'direct_post', name: 'My phone', onChallenge })

// 一覧・改名・解除
const { data: identities } = authClient.useListIdentities()
await authClient.concrnt.updateIdentity({ id, name })
await authClient.concrnt.deleteIdentity({ id })
```

`fragment` では Authenticator がブラウザで `redirect_uri#id_token=…` を開く。その URL (`/api/auth/concrnt/callback/<C>`) には
プラグインが小さな着地ページを返し、フラグメントを exchange に送ってから `callbackURL` へ遷移する。
アプリ側に実装は要らない。拒否や失敗のときは `callbackURL?error=<code>` に戻る。

## Concrnt だけでサインアップさせる

既定では未登録の CCID でのログインは `IDENTITY_NOT_FOUND` (401) になり、ユーザーは作られない (パスキーと同じ)。
Concrnt をサインアップ手段にするには、パスキーの「passkey-first registration」と同じ構成にする:

```ts
concrnt({
    registration: {
        requireSession: false,
        afterVerification: async ({ ctx, claims, user }) => {
            if (user) return // ログイン中のユーザーへの追加はそのまま
            const created = await ctx.context.internalAdapter.createUser(
                {
                    name: claims.name ?? claims.sub,
                    email: `${claims.sub}@example.invalid`, // better-auth の user には email が必須
                    emailVerified: false,
                    image: claims.picture ?? null
                },
                { method: 'concrnt' }
            )
            return { userId: created.id }
        }
    }
})
```

```ts
// ブラウザ: 登録と同時にセッションも作る
await authClient.concrnt.addIdentity({ createSession: true, onChallenge })
```

パスキーとの違いは 1 点だけ: `requireSession: false` でセッションも `resolveUser` も無いとき、パスキーは開始時に
`RESOLVE_USER_REQUIRED` を投げるが、このプラグインは開始を通し、受理時に `afterVerification` が `userId` を返すことを要求する
(返さなければ `RESOLVED_USER_INVALID`)。CCID とプロフィールクレームを見てからユーザーを作れるようにするため。
`claims.name` / `claims.picture` は Authenticator の自己申告なので表示用途に留めること (CIP-17 §7.3)。

## オプション

```ts
concrnt({
    origin?: string                 // RP のオリジン。既定は baseURL のオリジン
    clientMetadata?: ClientMetadata // §5.3 client_metadata。既定 { client_name: appName }
    requestTtl?: number             // Request Object の有効期間 (秒)。既定 300
    clockSkew?: number              // ID Token の iat 判定の許容幅 (秒)。既定 300
    registration?: {
        requireSession?: boolean    // 既定 true
        resolveUser?: ({ ctx, context }) => Awaitable<{ id: string; name?: string }>
        afterVerification?: ({ ctx, claims, user, context }) => Awaitable<{ userId?: string; name?: string } | void>
    }
    authentication?: {
        afterVerification?: ({ ctx, claims, identity }) => Awaitable<void>
    }
    landing?: Partial<{ title; working; denied; back }> // fragment 着地ページの文言
    schema?: InferOptionSchema<typeof schema>           // テーブル/列名の差し替え
})
```

## endpoint (basePath 配下)

| Method / Path | 役割 |
|---|---|
| `POST /concrnt/start-authentication` `{ callbackURL? }` | 要求を発行。`{ requestUri, directPostUri, fragmentUri, displayCode, exp, pollToken }` |
| `POST /concrnt/start-registration` `{ callbackURL?, name?, context?, createSession? }` | 同上。`requireSession` なら fresh なセッション必須 |
| `GET /concrnt/request/:C` | §5.3 Request Object (Authenticator が取る)。`Access-Control-Allow-Origin: *` |
| `POST /concrnt/callback/:C` | §8.1 direct_post の受け口。`application/x-www-form-urlencoded` の `id_token` / `error`。結果を開始したブラウザのために預け 204。**送信者にセッションは発行しない** |
| `GET /concrnt/callback/:C` | §8.2 fragment の着地ページ (HTML) |
| `POST /concrnt/exchange/:C` `{ id_token?, error? }` | §8.2 提示したブラウザにセッションを発行 |
| `GET /concrnt/status?pollToken=` | §8.1 開始したブラウザが結果を回収。`pending` / `denied` / `ok` (+セッション) |
| `GET /concrnt/list-identities` | 自分の identity 一覧 |
| `POST /concrnt/delete-identity` `{ id }` / `POST /concrnt/update-identity` `{ id, name }` | 所有者のみ |

`callbackURL` は better-auth の `trustedOrigins` で検証される。

## 安全性のメモ

- **受け口の役割は固定** (CIP-17 §8): `callback` への POST は預けるだけで、`exchange` は提示したブラウザをログインさせる。
  他人に fragment リンクを踏ませても、その人が自分でログインするだけで開始した側には何も届かない。
- **registration の照合** (パスキーと同じ): 開始時のユーザーと、結果を持ってきたブラウザのユーザーが違えば
  `YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_IDENTITY`。さらに fragment 経路では、提示したブラウザが開始したユーザーで
  ログインしていることを要求する (`SESSION_REQUIRED`)。開始したセッションに他人の応答を結び付けないため (§8.2)。
- **一回限り** (§9 手順 3): 使用済み記録は `reserveVerificationValue` (主キー衝突による first-writer-wins) で原子的に行い、
  同じ要求への同時応答は 1 件しか通らない。verification を secondaryStorage だけに置く構成では better-auth 側が拒否するので、
  DB 必須 (`verification.storeInDatabase`)。
- 着地ページのスクリプトは固定文字列で、`Content-Security-Policy: script-src 'sha256-…'` を付けて返す。

## エラーコード (`$ERROR_CODES`)

`CHALLENGE_NOT_FOUND` (404) · `CHALLENGE_ALREADY_USED` · `MISSING_ID_TOKEN` · `INVALID_ID_TOKEN` · `CEREMONY_NOT_FOUND` ·
`SESSION_REQUIRED` (401) · `RESOLVED_USER_INVALID` · `YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_IDENTITY` (401) ·
`IDENTITY_NOT_FOUND` (401) · `IDENTITY_ALREADY_REGISTERED` · `USER_NOT_FOUND` · `UNABLE_TO_CREATE_SESSION`

## サンプル

[`samples/better-auth`](../../samples/better-auth/README.md) — Cloudflare Workers + D1 + React。
