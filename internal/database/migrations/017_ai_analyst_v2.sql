-- 017_ai_analyst_v2: AI Analyst v2 audit columns (ai-security-analysis.md §5).
-- model_version + context_hash so a decision always states which model and
-- which evidence snapshot it decided on.

ALTER TABLE ai_analyses ADD COLUMN model_version TEXT;
ALTER TABLE ai_analyses ADD COLUMN context_hash TEXT;
