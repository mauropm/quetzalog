-- 018_detection_v2: detection rule model v2 + false-positive feedback.
-- All additions are additive: legacy threshold rules keep working unchanged
-- (kind defaults to 'threshold', version 1). Fixes the Update() column-loss
-- debt by giving every v2 field a column of its own.

ALTER TABLE detection_rules ADD COLUMN kind TEXT NOT NULL DEFAULT 'threshold';
ALTER TABLE detection_rules ADD COLUMN confidence REAL NOT NULL DEFAULT 0;
ALTER TABLE detection_rules ADD COLUMN mitre_techniques TEXT NOT NULL DEFAULT '[]';
ALTER TABLE detection_rules ADD COLUMN tactic_ids TEXT NOT NULL DEFAULT '[]';
ALTER TABLE detection_rules ADD COLUMN required_sources TEXT NOT NULL DEFAULT '[]';
ALTER TABLE detection_rules ADD COLUMN fp_notes TEXT NOT NULL DEFAULT '';
ALTER TABLE detection_rules ADD COLUMN reference_links TEXT NOT NULL DEFAULT '[]';
ALTER TABLE detection_rules ADD COLUMN response_actions TEXT NOT NULL DEFAULT '[]';
ALTER TABLE detection_rules ADD COLUMN definition TEXT NOT NULL DEFAULT '';
ALTER TABLE detection_rules ADD COLUMN version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE detection_rules ADD COLUMN test_events TEXT NOT NULL DEFAULT '[]';
ALTER TABLE detection_rules ADD COLUMN last_run_at DATETIME;
ALTER TABLE detection_rules ADD COLUMN suppressed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE detection_rules ADD COLUMN suppressed_by TEXT NOT NULL DEFAULT '';
ALTER TABLE detection_rules ADD COLUMN suppress_reason TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_detection_rules_kind ON detection_rules(kind);

-- False-positive / analyst feedback per finding (spec §55).
-- Labels: true_positive | false_positive | benign | expected_behavior | accepted_risk.
-- reason is REQUIRED for false_positive and accepted_risk (enforced at API layer).
CREATE TABLE IF NOT EXISTS finding_feedback (
    finding_id TEXT NOT NULL,
    label TEXT NOT NULL CHECK (label IN ('true_positive', 'false_positive', 'benign', 'expected_behavior', 'accepted_risk')),
    reason TEXT NOT NULL DEFAULT '',
    analyst TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (finding_id, analyst)
);

CREATE INDEX IF NOT EXISTS idx_finding_feedback_label ON finding_feedback(label);
