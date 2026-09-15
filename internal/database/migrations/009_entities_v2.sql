-- 009_entities_v2.sql: Entity resolution & relationship provenance
-- (Phase 2 Inc-4).
--
-- The hot-write 5-tuple tables (entities, relationships) are untouched;
-- v2 adds:
--   entity_identities   alias -> canonical resolution with explicit
--                       status/confidence/source, never aggressive merges
--   entity_meta         rich per-entity metadata (OS, environment,
--                       privilege, cloud context, tags)
--   relationship_meta   edge state + provenance (who said it, when,
--                       what supports it) alongside the hot edge table
--
-- State semantics: observed (write path only) / inferred (rules, AI —
-- always with source_type+source_id) / potential (attack-graph
-- reasoning, recomputed) / blocked (deny/block events).

CREATE TABLE IF NOT EXISTS entity_identities (
    id TEXT PRIMARY KEY,
    canonical_type TEXT NOT NULL,
    canonical_value TEXT NOT NULL,
    alias_type TEXT NOT NULL,
    alias_value TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unknown'
        CHECK (status IN ('confirmed','probable','possible','unknown')),
    confidence REAL NOT NULL DEFAULT 0.5,
    source TEXT NOT NULL DEFAULT 'observation',
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    UNIQUE(canonical_type, canonical_value, alias_type, alias_value)
);

CREATE INDEX IF NOT EXISTS idx_entity_identities_alias
    ON entity_identities(alias_type, alias_value);
CREATE INDEX IF NOT EXISTS idx_entity_identities_canonical
    ON entity_identities(canonical_type, canonical_value);

CREATE TABLE IF NOT EXISTS entity_meta (
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    display_name TEXT,
    os TEXT,
    os_version TEXT,
    environment TEXT,
    internet_exposed INTEGER,
    privilege TEXT,
    cloud_provider TEXT,
    cloud_account TEXT,
    tags TEXT,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (type, value)
);

CREATE TABLE IF NOT EXISTS relationship_meta (
    from_type TEXT NOT NULL,
    from_value TEXT NOT NULL,
    to_type TEXT NOT NULL,
    to_value TEXT NOT NULL,
    relation TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'observed'
        CHECK (status IN ('observed','inferred','potential','blocked')),
    source_type TEXT NOT NULL DEFAULT 'event',
    source_id TEXT,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    evidence TEXT,
    PRIMARY KEY (from_type, from_value, to_type, to_value, relation)
);

CREATE INDEX IF NOT EXISTS idx_relationship_meta_source
    ON relationship_meta(source_type, source_id);
