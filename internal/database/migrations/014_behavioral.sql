-- 014_behavioral: rolling baselines + anomaly log for statistical/behavioral
-- detection (detection-engine.md §4, risk-model.md §5).
--
-- Baselines are per-entity, per-feature rolling stats. A feature is only
-- "trusted" once it has >= 20 samples over >= 14 days; below that the
-- engine must not score (no telemetry != no activity).

CREATE TABLE IF NOT EXISTS baselines (
    entity_type TEXT NOT NULL,
    entity_value TEXT NOT NULL,
    feature TEXT NOT NULL,
    window_days INTEGER NOT NULL DEFAULT 30,
    mean REAL,
    stddev REAL,
    p95 REAL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    last_updated DATETIME NOT NULL,
    PRIMARY KEY (entity_type, entity_value, feature, window_days)
);

CREATE INDEX IF NOT EXISTS idx_baselines_feature ON baselines(feature);

CREATE TABLE IF NOT EXISTS anomalies (
    id TEXT PRIMARY KEY,
    entity_type TEXT,
    entity_value TEXT,
    feature TEXT,
    observed REAL,
    baseline_mean REAL,
    z REAL,
    detected_at DATETIME NOT NULL,
    detection_id TEXT,
    suppressed_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_anomalies_entity ON anomalies(entity_type, entity_value, detected_at);
CREATE INDEX IF NOT EXISTS idx_anomalies_detection ON anomalies(detection_id);
