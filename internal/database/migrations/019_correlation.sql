-- 019_correlation: shared state for sequence + correlation detection rules
-- (detection-engine.md §2-3). One row per (rule, correlation-key hash).
-- Sequences: ordered steps, current_step = furthest satisfied step.
-- Correlations: unordered conditions; evidence holds the windowed events.
-- Pruned by the correlation engine sweeper (expired states, 15-min cadence).

CREATE TABLE IF NOT EXISTS correlation_state (
    rule_id TEXT NOT NULL,
    state_key TEXT NOT NULL,
    current_step INTEGER NOT NULL DEFAULT 0,
    step_first_event TEXT,
    last_event_at DATETIME NOT NULL,
    evidence TEXT NOT NULL DEFAULT '[]',
    expires_at DATETIME NOT NULL,
    PRIMARY KEY (rule_id, state_key)
);

CREATE INDEX IF NOT EXISTS idx_correlation_state_expires ON correlation_state(expires_at);
CREATE INDEX IF NOT EXISTS idx_correlation_state_rule ON correlation_state(rule_id);
