-- Event tokens: shareable ingest API keys for log injection.
-- The full token is stored ENCRYPTED (AES-256-GCM) so admins can re-copy
-- it; a SHA-256 hash drives fast constant-time validation.
CREATE TABLE IF NOT EXISTS event_tokens (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    tag TEXT NOT NULL DEFAULT '',
    grp TEXT NOT NULL DEFAULT '',
    token_hash TEXT NOT NULL UNIQUE,
    token_enc BLOB NOT NULL,
    token_prefix TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_event_tokens_hash ON event_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_event_tokens_grp ON event_tokens(grp);
