-- 016_coverage.sql: Telemetry coverage per asset (Phase 2 Inc-5).
--
-- Coverage is OBSERVED, not declared: which source classes actually emit
-- telemetry for an asset, how fresh it is, and which classes the analyst
-- declared expected. The invariant (docs/telemetry-coverage.md §1):
-- missing telemetry yields "unknown", never a negative claim.

CREATE TABLE IF NOT EXISTS asset_telemetry (
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    source_class TEXT NOT NULL,
    available INTEGER NOT NULL DEFAULT 0,
    last_event DATETIME,
    event_count_30d INTEGER NOT NULL DEFAULT 0,
    expected INTEGER NOT NULL DEFAULT 0,
    collector TEXT,
    PRIMARY KEY (asset_id, source_class)
);

CREATE INDEX IF NOT EXISTS idx_asset_telemetry_class
    ON asset_telemetry(source_class);
