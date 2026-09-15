-- 012_attack_graph: materialized attack paths (observed/inferred/potential).
-- Potential paths are recomputed on every sweep and never persisted as
-- observed (attack-graph.md §5): they disappear when their precondition
-- vanishes.

CREATE TABLE IF NOT EXISTS attack_paths (
  id TEXT PRIMARY KEY,
  scenario_run_id TEXT,
  source_node TEXT NOT NULL,        -- 'type:value'
  target_node TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('observed','inferred','potential')),
  description TEXT,
  risk REAL,
  created_by TEXT,
  created_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attack_paths_status ON attack_paths (status);
CREATE INDEX IF NOT EXISTS idx_attack_paths_target ON attack_paths (target_node);

CREATE TABLE IF NOT EXISTS path_steps (
  path_id TEXT NOT NULL,
  pos INTEGER NOT NULL,
  from_node TEXT NOT NULL,
  to_node TEXT NOT NULL,
  edge_relation TEXT NOT NULL,
  edge_state TEXT NOT NULL,
  technique TEXT,
  evidence TEXT,                    -- JSON event ids / detection id / reasoning ref
  PRIMARY KEY (path_id, pos)
);
