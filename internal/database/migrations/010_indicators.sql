-- 010_indicators.sql: Threat-intel indicator model (Phase 3 Inc-6).
--
-- External TI is untrusted input (architecture doc, principle 10): provider
-- payloads are validated and quarantined in these tables. A single weak
-- source cannot classify an indicator malicious — the aggregate confidence
-- is corroborated across sources (see internal/threatintel/store.go).

CREATE TABLE IF NOT EXISTS indicators (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    description TEXT,
    source TEXT NOT NULL DEFAULT 'analyst',
    confidence REAL NOT NULL DEFAULT 0,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    hit_count INTEGER NOT NULL DEFAULT 0,
    attributes TEXT,
    UNIQUE(type, normalized_value)
);

CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(type, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_indicators_norm ON indicators(normalized_value);

-- Per-source provenance: every provider/analyst that reported the indicator.
CREATE TABLE IF NOT EXISTS indicator_sources (
    indicator_id TEXT NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    source_url TEXT,
    reliability REAL NOT NULL DEFAULT 0.5,
    confidence REAL NOT NULL DEFAULT 0.5,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    PRIMARY KEY (indicator_id, source)
);

CREATE TABLE IF NOT EXISTS threat_actors (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    aka TEXT,
    type TEXT,
    country TEXT,
    motivation TEXT,
    description TEXT,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL
);

-- Attribution ladder (principle 7): associated < consistent <
-- possibly_related < attributed.
CREATE TABLE IF NOT EXISTS actor_indicators (
    actor_id TEXT NOT NULL REFERENCES threat_actors(id) ON DELETE CASCADE,
    indicator_id TEXT NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
    attribution TEXT NOT NULL DEFAULT 'associated',
    PRIMARY KEY (actor_id, indicator_id)
);

CREATE TABLE IF NOT EXISTS campaigns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    actor_id TEXT REFERENCES threat_actors(id) ON DELETE SET NULL,
    description TEXT,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS campaign_indicators (
    campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    indicator_id TEXT NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
    PRIMARY KEY (campaign_id, indicator_id)
);

CREATE TABLE IF NOT EXISTS malware_families (
    id TEXT PRIMARY KEY,
    family TEXT NOT NULL UNIQUE,
    description TEXT,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS malware_indicators (
    malware_id TEXT NOT NULL REFERENCES malware_families(id) ON DELETE CASCADE,
    indicator_id TEXT NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
    PRIMARY KEY (malware_id, indicator_id)
);

-- Observed co-occurrence: two indicators seen in the same event.
CREATE TABLE IF NOT EXISTS indicator_correlations (
    from_id TEXT NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
    to_id TEXT NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
    event_id TEXT,
    observed_at DATETIME NOT NULL,
    PRIMARY KEY (from_id, to_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_indicator_correlations_from ON indicator_correlations(from_id);

CREATE TABLE IF NOT EXISTS ti_provider_state (
    provider TEXT PRIMARY KEY,
    last_sync DATETIME,
    last_status TEXT,
    last_error TEXT,
    indicator_count INTEGER NOT NULL DEFAULT 0
);
