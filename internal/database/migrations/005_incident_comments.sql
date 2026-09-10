-- 005_incident_comments.sql: timeline comments attached to incidents
CREATE TABLE IF NOT EXISTS incident_comments (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    author TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_incident_comments_incident ON incident_comments(incident_id, created_at);
