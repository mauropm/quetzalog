-- 013_threat_models: multi-framework threat models derived from telemetry
-- (threat-model.md §1). All new tables; no existing table touched.

CREATE TABLE IF NOT EXISTS threat_models (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('analyst','telemetry','hybrid')),
  version INTEGER NOT NULL DEFAULT 1,
  scope TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS tm_nodes (
  model_id TEXT NOT NULL,
  node_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN
    ('asset','trust_boundary','identity','entry_point','data_store','process',
     'network','dependency','application','cloud_resource')),
  label TEXT NOT NULL,
  entity_ref TEXT,
  label_state TEXT NOT NULL CHECK (label_state IN ('observed','inferred','assumed')),
  attrs TEXT,
  PRIMARY KEY (model_id, node_id)
);
CREATE INDEX IF NOT EXISTS idx_tm_nodes_model ON tm_nodes (model_id);
CREATE INDEX IF NOT EXISTS idx_tm_nodes_entity ON tm_nodes (entity_ref);

CREATE TABLE IF NOT EXISTS tm_edges (
  model_id TEXT NOT NULL,
  from_node TEXT NOT NULL,
  to_node TEXT NOT NULL,
  relation TEXT NOT NULL,
  label_state TEXT NOT NULL CHECK (label_state IN ('observed','inferred','assumed')),
  evidence TEXT,
  PRIMARY KEY (model_id, from_node, to_node, relation)
);
CREATE INDEX IF NOT EXISTS idx_tm_edges_model ON tm_edges (model_id);

CREATE TABLE IF NOT EXISTS threats (
  model_id TEXT NOT NULL,
  threat_id TEXT NOT NULL,
  node_id TEXT,
  edge_id TEXT,
  description TEXT NOT NULL,
  stride TEXT CHECK (stride IN ('spoofing','tampering','repudiation',
    'information_disclosure','denial_of_service','elevation_of_privilege')),
  kill_chain_phase TEXT,
  techniques TEXT,
  d3fend_mitigations TEXT,
  likelihood TEXT CHECK (likelihood IN ('rare','possible','likely','almost_certain','unknown')),
  impact TEXT CHECK (impact IN ('low','medium','high','critical','unknown')),
  label_state TEXT NOT NULL CHECK (label_state IN ('observed','inferred','assumed')),
  PRIMARY KEY (model_id, threat_id)
);
CREATE INDEX IF NOT EXISTS idx_threats_model ON threats (model_id);

CREATE TABLE IF NOT EXISTS controls (
  control_id TEXT PRIMARY KEY,
  framework TEXT NOT NULL,
  ref TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT
);

CREATE TABLE IF NOT EXISTS threat_controls (
  threat_ref TEXT NOT NULL,      -- 'model:<id>:threat:<tid>' or global
  control_id TEXT NOT NULL,
  mapping_state TEXT NOT NULL CHECK (mapping_state IN ('observed','inferred','assumed')),
  evidence TEXT,
  PRIMARY KEY (threat_ref, control_id)
);

CREATE TABLE IF NOT EXISTS model_snapshots (   -- drift tracking (spec §50)
  model_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  snapshot TEXT NOT NULL,
  changes TEXT NOT NULL,
  triggered_by TEXT,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (model_id, version)
);
