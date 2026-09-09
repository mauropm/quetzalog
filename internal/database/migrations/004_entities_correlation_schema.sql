-- Align entities/relationships with the schema expected by internal/correlation.
-- The original 001 created entities(entity_type, entity_value) with no
-- relationships table, so entity correlation never populated or queried. Both
-- tables are rebuilt here from scratch; their rows are derived from events and
-- repopulated automatically on ingestion. Timestamps use DATETIME so the driver
-- round-trips them as time.Time.
DROP TABLE IF EXISTS entities;
DROP TABLE IF EXISTS relationships;

CREATE TABLE entities (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    first_seen DATETIME NOT NULL DEFAULT (datetime('now')),
    last_seen DATETIME NOT NULL DEFAULT (datetime('now')),
    count INTEGER NOT NULL DEFAULT 1,
    metadata TEXT,
    UNIQUE(type, value)
);

CREATE INDEX idx_entities_type_value ON entities(type, value);

CREATE TABLE relationships (
    id TEXT PRIMARY KEY,
    from_type TEXT NOT NULL,
    from_value TEXT NOT NULL,
    to_type TEXT NOT NULL,
    to_value TEXT NOT NULL,
    relation TEXT NOT NULL,
    weight INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE(from_type, from_value, to_type, to_value, relation)
);

CREATE INDEX idx_relationships_from ON relationships(from_type, from_value);
CREATE INDEX idx_relationships_to ON relationships(to_type, to_value);
CREATE INDEX idx_relationships_relation ON relationships(relation);
CREATE INDEX idx_relationships_created ON relationships(created_at);
