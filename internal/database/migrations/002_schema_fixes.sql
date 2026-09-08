CREATE TABLE IF NOT EXISTS notes (
    id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    content TEXT NOT NULL,
    author TEXT,
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_notes_alert ON notes(alert_id);
CREATE INDEX IF NOT EXISTS idx_notes_created ON notes(created_at);

ALTER TABLE incidents ADD COLUMN alert_ids TEXT NOT NULL DEFAULT '[]';
ALTER TABLE incidents ADD COLUMN event_ids TEXT NOT NULL DEFAULT '[]';
ALTER TABLE incidents ADD COLUMN entity_ids TEXT NOT NULL DEFAULT '[]';

CREATE TABLE IF NOT EXISTS api_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id);

CREATE TABLE audit_log_new (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    details TEXT,
    ip TEXT,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

INSERT INTO audit_log_new (id, user_id, action, resource, details, ip, created_at)
SELECT id, user, action, resource, details, ip_address, timestamp FROM audit_log;

DROP TABLE audit_log;
ALTER TABLE audit_log_new RENAME TO audit_log;

CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at);
