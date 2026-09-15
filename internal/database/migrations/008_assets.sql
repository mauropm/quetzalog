-- 008_assets.sql: Assets & software inventory (Phase 2 Inc-3).
--
-- Assets are first-class security objects. entity_ref (a "type:value"
-- graph key, e.g. 'host:WORKSTATION-42') links an asset to the correlation
-- graph without touching the hot-write entity 5-tuple.
--
-- Two creation paths:
--   observed: auto-created as a DRAFT on the first event naming the host
--     (created_by='observed', tagged "draft" + "criticality-suggested:<x>").
--     Drafts never influence scoring until an analyst confirms criticality
--     (medium is used meanwhile; the suggestion is advisory only).
--   analyst:  created/edited via API/UI with full fields.

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL CHECK (entity_type IN (
        'host','server','workstation','container','cloud_resource',
        'database','application','identity_provider','network')),
    entity_ref TEXT NOT NULL,
    name TEXT NOT NULL,
    os TEXT,
    os_version TEXT,
    environment TEXT,
    criticality TEXT NOT NULL DEFAULT 'medium'
        CHECK (criticality IN ('critical','high','medium','low')),
    owner TEXT,
    business_unit TEXT,
    location TEXT,
    data_classification TEXT,
    internet_exposed INTEGER NOT NULL DEFAULT 0,
    tags TEXT,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    created_by TEXT,
    updated_at DATETIME NOT NULL,
    UNIQUE(entity_type, entity_ref)
);

CREATE INDEX IF NOT EXISTS idx_assets_entity_type ON assets(entity_type);
CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(criticality);

CREATE TABLE IF NOT EXISTS asset_aliases (
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    alias_type TEXT NOT NULL,
    alias_value TEXT NOT NULL,
    UNIQUE(asset_id, alias_type, alias_value)
);

CREATE INDEX IF NOT EXISTS idx_asset_aliases_value ON asset_aliases(alias_value);

CREATE TABLE IF NOT EXISTS asset_software (
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    vendor TEXT,
    version TEXT,
    cpe TEXT,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    source TEXT,
    PRIMARY KEY (asset_id, name, version)
);

CREATE TABLE IF NOT EXISTS asset_vulnerabilities (
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    cve TEXT NOT NULL,
    severity TEXT,
    cvss REAL,
    epss REAL,
    exploit_available TEXT
        CHECK (exploit_available IN ('in-the-wild','public-poc','theoretical','unknown')),
    evidence TEXT,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    PRIMARY KEY (asset_id, cve)
);
