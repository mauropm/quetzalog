-- 006_soc_schema.sql: Security Operations layer.
-- Adds findings (analyst queue), investigations (workbench), entity risk,
-- saved queue views, response action ledger and MITRE/risk metadata on
-- detection rules. All new tables; detection_rules is extended in place.

-- findings: triage-level security findings aggregated from detection runs
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'new',
    risk_score REAL NOT NULL DEFAULT 0,
    detection_id TEXT,
    detection_name TEXT,
    dedup_key TEXT,
    user TEXT,
    host TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    data_source TEXT,
    mitre_tactic TEXT,
    mitre_technique TEXT,
    owner TEXT,
    tags TEXT NOT NULL DEFAULT '[]',
    alert_ids TEXT NOT NULL DEFAULT '[]',
    event_ids TEXT NOT NULL DEFAULT '[]',
    entities TEXT NOT NULL DEFAULT '[]',
    match_count INTEGER NOT NULL DEFAULT 0,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE(dedup_key)
);

CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_detection ON findings(detection_id);
CREATE INDEX IF NOT EXISTS idx_findings_user ON findings(user);
CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host);
CREATE INDEX IF NOT EXISTS idx_findings_source_ip ON findings(source_ip);
CREATE INDEX IF NOT EXISTS idx_findings_tactic ON findings(mitre_tactic);
CREATE INDEX IF NOT EXISTS idx_findings_technique ON findings(mitre_technique);
CREATE INDEX IF NOT EXISTS idx_findings_last_seen ON findings(last_seen);
CREATE INDEX IF NOT EXISTS idx_findings_owner ON findings(owner);

-- finding_notes: analyst notes attached to findings
CREATE TABLE IF NOT EXISTS finding_notes (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    content TEXT NOT NULL,
    author TEXT,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_finding_notes_finding ON finding_notes(finding_id, created_at);

-- investigations: persistent analyst workbench collecting the security story
CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT,
    status TEXT NOT NULL DEFAULT 'new',
    assignee TEXT,
    finding_ids TEXT NOT NULL DEFAULT '[]',
    event_ids TEXT NOT NULL DEFAULT '[]',
    entities TEXT NOT NULL DEFAULT '[]',
    queries TEXT NOT NULL DEFAULT '[]',
    techniques TEXT NOT NULL DEFAULT '[]',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status);
CREATE INDEX IF NOT EXISTS idx_investigations_severity ON investigations(severity);
CREATE INDEX IF NOT EXISTS idx_investigations_assignee ON investigations(assignee);

-- investigation_notes: authored timeline notes (timestamp + author + id)
CREATE TABLE IF NOT EXISTS investigation_notes (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    author TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_investigation_notes_inv ON investigation_notes(investigation_id, created_at);

-- entity_risk: accumulated risk per entity, rebuilt from risk contributions
CREATE TABLE IF NOT EXISTS entity_risk (
    entity_type TEXT NOT NULL,
    entity_value TEXT NOT NULL,
    risk_score REAL NOT NULL DEFAULT 0,
    contribution_count INTEGER NOT NULL DEFAULT 0,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (entity_type, entity_value)
);

CREATE INDEX IF NOT EXISTS idx_entity_risk_score ON entity_risk(risk_score);

-- risk_contributions: transparent breakdown of where an entity's risk comes from
CREATE TABLE IF NOT EXISTS risk_contributions (
    id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,
    entity_value TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_id TEXT,
    description TEXT,
    points REAL NOT NULL,
    event_id TEXT,
    created_at DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_risk_contributions_entity ON risk_contributions(entity_type, entity_value, created_at);

-- saved_views: per-user saved analyst queue views
CREATE TABLE IF NOT EXISTS saved_views (
    id TEXT PRIMARY KEY,
    user TEXT NOT NULL,
    name TEXT NOT NULL,
    filters TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_saved_views_user ON saved_views(user, name);

-- response_actions: audit ledger for executed response actions
CREATE TABLE IF NOT EXISTS response_actions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    details TEXT,
    user TEXT,
    status TEXT NOT NULL DEFAULT 'ok',
    created_at DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_response_actions_created ON response_actions(created_at);
CREATE INDEX IF NOT EXISTS idx_response_actions_action ON response_actions(action);

-- detection_rules: SOC metadata (risk, MITRE, tags, schedule, provenance)
ALTER TABLE detection_rules ADD COLUMN risk_score REAL NOT NULL DEFAULT 0;
ALTER TABLE detection_rules ADD COLUMN tags TEXT NOT NULL DEFAULT '[]';
ALTER TABLE detection_rules ADD COLUMN mitre_tactic TEXT;
ALTER TABLE detection_rules ADD COLUMN mitre_technique TEXT;
ALTER TABLE detection_rules ADD COLUMN schedule_seconds INTEGER NOT NULL DEFAULT 0;
ALTER TABLE detection_rules ADD COLUMN created_by TEXT;
ALTER TABLE detection_rules ADD COLUMN data_sources TEXT NOT NULL DEFAULT '[]';
