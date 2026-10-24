# concrnt-auth-client

[CIP-17: External Service Authentication (Sign-In with Concrnt)](https://github.com/concrnt/CIPs) の
RP (Relying Party) 側の実装群。pnpm workspace。

| パッケージ | 内容 |
|---|---|
| [`packages/auth-client`](packages/auth-client/README.md) — `@concrnt/auth-client` | RP コア。HTTP フレームワークに依存しない。要求の発行・応答の受理・ID Token の検証。ストア (`AuthStore`) を注入して使う |
| [`packages/better-auth`](packages/better-auth/README.md) — `@concrnt/better-auth` | [better-auth](https://www.better-auth.com) プラグイン。`plugins: [concrnt()]` で Concrnt ログインが付く。CCID は標準の `account` テーブルに入り、専用テーブルは無い |
| [`samples/auth-client`](samples/auth-client/README.md) | コアを直接使う最小サンプル (Cloudflare Workers + KV + React)。デプロイ済み: <https://auth-client-sample.concrnt.net> |
| [`samples/better-auth`](samples/better-auth/README.md) | better-auth プラグインのサンプル (Cloudflare Workers + D1 + React)。デプロイ済み: <https://better-auth-sample.concrnt.net> |

```sh
pnpm install
pnpm build       # packages/* を dist/ へ (samples は dist を参照する)
pnpm test
pnpm typecheck
pnpm lint
```
