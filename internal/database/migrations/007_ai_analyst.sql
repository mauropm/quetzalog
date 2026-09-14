-- 007_ai_analyst.sql: AI Analyst layer.
-- One analysis row per finding (deduplication at the finding level): the
-- finding itself is already the correlation of the raw events, so 100 failed
-- logins from one IP yield at most one AI analysis.
--
-- Lifecycle: analyzing -> analyzed -> approved | dismissed
--                     \-> failed -> (re-analyze overwrites the row)
-- No execution state exists on purpose: the AI Analyst only records
-- recommendations; consequential actions require a separate, human-approved
-- framework (not wired in this migration).

CREATE TABLE IF NOT EXISTS ai_analyses (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL UNIQUE,
    -- analyzing | analyzed | failed | approved | dismissed
    status TEXT NOT NULL DEFAULT 'analyzing',
    provider TEXT,
    model TEXT,
    prompt_version TEXT,
    prompt_hash TEXT,
    -- JSON: evidence snapshot sent to the model (finding, events, related
    -- findings, entities). Never contains credentials or API keys.
    context TEXT NOT NULL DEFAULT '{}',
    -- JSON: validated structured analysis (title, summary, severity,
    -- confidence, evidence, alternative_explanations, recommended_action...).
    -- Empty until the analysis succeeds.
    analysis TEXT,
    error TEXT,
    confidence REAL,
    severity TEXT,
    recommendation_type TEXT,
    decision TEXT,
    decision_reason TEXT,
    decided_by TEXT,
    decided_at DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_analyses_status ON ai_analyses(status);
CREATE INDEX IF NOT EXISTS idx_ai_analyses_severity ON ai_analyses(severity);
CREATE INDEX IF NOT EXISTS idx_ai_analyses_updated ON ai_analyses(updated_at);
