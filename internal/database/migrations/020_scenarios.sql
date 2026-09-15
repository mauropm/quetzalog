-- 020_scenarios: threat-scenario runs (detection-engine.md §6).
-- A scenario run is an instance of a composable attack chain evaluated
-- against events + telemetry coverage. Step statuses:
--   observed  evidence events exist
--   blocked   deny/blocked events exist
--   missing   no events AND required telemetry present (evidence it likely
--             did not happen, within telemetry bounds)
--   unknown   no events AND required telemetry missing (spec §25: "telemetry
--             insufficient to determine whether ... occurred")
--   expected  next-likely action in the chain (run still young)

CREATE TABLE IF NOT EXISTS scenario_runs (
    id TEXT PRIMARY KEY,
    definition TEXT NOT NULL,
    scope TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    confidence REAL,
    risk REAL,
    opened_at DATETIME,
    closed_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_scenario_runs_status ON scenario_runs(status);

CREATE TABLE IF NOT EXISTS scenario_steps (
    run_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    tactic TEXT,
    technique TEXT,
    status TEXT NOT NULL CHECK (status IN ('observed', 'expected', 'missing', 'unknown', 'blocked')),
    evidence TEXT,
    confidence REAL,
    PRIMARY KEY (run_id, step_id)
);
