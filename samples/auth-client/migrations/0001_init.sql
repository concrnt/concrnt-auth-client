-- @concrnt/auth-client の AuthStore (worker/store.ts)。要求ごとの行と別端末フローの結果。数分で期限切れになる
CREATE TABLE login_store (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    expires_at INTEGER NOT NULL -- UNIX 秒
);
CREATE INDEX login_store_expires_at ON login_store (expires_at);

-- ログイン後のセッション (worker/session.ts)。CIP-17 の範囲外で RP 固有。cookie のトークンが主キー
CREATE TABLE login_session (
    token TEXT PRIMARY KEY,
    ccid TEXT NOT NULL,
    domain TEXT NOT NULL,
    name TEXT,
    picture TEXT,
    expires_at INTEGER NOT NULL -- UNIX 秒
);
CREATE INDEX login_session_expires_at ON login_session (expires_at);
