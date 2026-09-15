package detections

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"quetzalog/internal/assets"
	"quetzalog/internal/coverage"
	"quetzalog/internal/events"
	"quetzalog/internal/findings"
	"quetzalog/pkg/event"
	"gopkg.in/yaml.v3"
)

//go:embed scenarios/*.yaml
var scenarioFS embed.FS

// ScenarioDef is one reusable attack chain (data, not code — spec §25, §53).
type ScenarioDef struct {
	Name               string   `yaml:"name" json:"name"`
	Title              string   `yaml:"title" json:"title"`
	Description        string   `yaml:"description" json:"description"`
	Risk               string   `yaml:"risk" json:"risk"`
	Severity           string   `yaml:"severity" json:"severity"`
	Trigger            string   `yaml:"trigger" json:"trigger"`
	Prerequisites      []string `yaml:"prerequisites,omitempty" json:"prerequisites,omitempty"`
	ExpectedTechniques []string `yaml:"expected_techniques" json:"expected_techniques"`
	RequiredSources    []string `yaml:"required_sources,omitempty" json:"required_sources,omitempty"`
}

// ScenarioRun mirrors one scenario_runs row.
type ScenarioRun struct {
	ID         string          `json:"id"`
	Definition json.RawMessage `json:"definition"`
	Scope      string          `json:"scope,omitempty"`
	Status     string          `json:"status"`
	Confidence float64         `json:"confidence"`
	Risk       float64         `json:"risk"`
	OpenedAt   time.Time       `json:"opened_at"`
	ClosedAt   sql.NullTime    `json:"closed_at,omitempty"`
}

// ScenarioStep mirrors one scenario_steps row.
type ScenarioStep struct {
	RunID      string    `json:"run_id"`
	StepID     string    `json:"step_id"`
	Tactic     string    `json:"tactic,omitempty"`
	Technique  string    `json:"technique,omitempty"`
	Status     string    `json:"status"`
	Evidence   string    `json:"evidence,omitempty"`
	Confidence float64   `json:"confidence"`
}

// WhatNext lists the steps an analyst should anticipate next: expected
// (next-likely in the chain) and unknown (telemetry gaps, spec §25).
type WhatNext struct {
	Expected []ScenarioStep `json:"expected"`
	Unknown  []ScenarioStep `json:"unknown"`
}

// ScenarioEvaluator opens and advances scenario runs from detection
// findings. Runs are evaluated by an async ticker (never on the write
// path); new findings are picked up within one tick.
type ScenarioEvaluator struct {
	db           *sql.DB
	evStore      *events.Store
	findingStore *findings.Store
	assetStore   *assets.Store
	coverage     *coverage.Store
	logger       func(msg string, kv ...any)
}

// NewScenarioEvaluator creates the evaluator.
func NewScenarioEvaluator(db *sql.DB, evStore *events.Store, findingStore *findings.Store, assetStore *assets.Store, coverageStore *coverage.Store, logger func(msg string, kv ...any)) *ScenarioEvaluator {
	return &ScenarioEvaluator{
		db:           db,
		evStore:      evStore,
		findingStore: findingStore,
		assetStore:   assetStore,
		coverage:     coverageStore,
		logger:       logger,
	}
}

// ListScenarios returns the embedded scenario definitions.
func ListScenarios() ([]ScenarioDef, error) {
	entries, err := scenarioFS.ReadDir("scenarios")
	if err != nil {
		return nil, fmt.Errorf("read scenarios dir: %w", err)
	}
	out := make([]ScenarioDef, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := scenarioFS.ReadFile("scenarios/" + e.Name())
		if err != nil {
			return nil, err
		}
		var def ScenarioDef
		if err := yamlUnmarshal(data, &def); err != nil {
			return nil, fmt.Errorf("parse scenario %s: %w", e.Name(), err)
		}
		if def.Name == "" {
			def.Name = strings.TrimSuffix(e.Name(), ".yaml")
		}
		out = append(out, def)
	}
	return out, nil
}

// Evaluate opens runs for trigger findings and advances active runs.
// Returns the number of steps that changed status.
func (e *ScenarioEvaluator) Evaluate(ctx context.Context, now time.Time) (int, error) {
	defs, err := ListScenarios()
	if err != nil {
		return 0, err
	}
	changed := 0
	for i := range defs {
		def := defs[i]
		if err := e.evaluateOne(ctx, &def, now); err != nil {
			e.log("scenario evaluate", "scenario", def.Name, "error", err)
			continue
		}
	}
	changed = e.advanceActiveRuns(ctx, now)
	return changed, nil
}

func (e *ScenarioEvaluator) evaluateOne(ctx context.Context, def *ScenarioDef, now time.Time) error {
	// Trigger: a finding (or mapped event) carrying the trigger technique on
	// a host, within the last 6h, not already tied to an active run.
	rows, err := e.db.QueryContext(ctx,
		`SELECT host, MIN(timestamp) FROM events
		 WHERE host != ''
		   AND timestamp >= ?
		   AND json_extract(attributes, '$."mitre"."attack"') LIKE ?
		 GROUP BY host`,
		now.Add(-6*time.Hour), "%\""+def.Trigger+"\"%")
	if err != nil {
		return fmt.Errorf("trigger events: %w", err)
	}
	type trig struct {
		host string
		at   time.Time
	}
	trigs := []trig{}
	for rows.Next() {
		var h string
		var atStr string
		if err := rows.Scan(&h, &atStr); err != nil {
			rows.Close()
			return err
		}
		trigs = append(trigs, trig{host: h, at: parseEventTime(atStr, now)})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for _, tr := range trigs {
		host := tr.host
		scope := "host:" + host
		var n int
		_ = e.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM scenario_runs WHERE definition LIKE ? AND scope = ? AND status = 'active'`,
			"%"+"\"name\":\""+def.Name, scope).Scan(&n)
		if n > 0 {
			continue
		}
		// opened_at = trigger time, so the step window captures the trigger
		// evidence plus everything after it.
		if tr.at.IsZero() {
			tr.at = now
		}
		defJSON, _ := json.Marshal(def)
		id := newID()
		if _, err := e.db.ExecContext(ctx,
			`INSERT INTO scenario_runs (id, definition, scope, status, opened_at)
			 VALUES (?, ?, ?, 'active', ?)`,
			id, string(defJSON), scope, tr.at); err != nil {
			return fmt.Errorf("open scenario run: %w", err)
		}
		e.log("scenario opened", "scenario", def.Name, "scope", scope, "run", id)
		_, err = e.advanceRun(ctx, id, def, now)
		if err != nil {
			return err
		}
	}
	return nil
}

// advanceActiveRuns re-evaluates every active run; returns steps changed.
func (e *ScenarioEvaluator) advanceActiveRuns(ctx context.Context, now time.Time) int {
	rows, err := e.db.QueryContext(ctx,
		`SELECT id, definition FROM scenario_runs WHERE status = 'active'`)
	if err != nil {
		e.log("list active runs", "error", err)
		return 0
	}
	defer rows.Close()
	type active struct {
		id string
		def ScenarioDef
	}
	actives := []active{}
	for rows.Next() {
		var id string
		var defJSON []byte
		if err := rows.Scan(&id, &defJSON); err != nil {
			e.log("scan active run", "error", err)
			continue
		}
		var def ScenarioDef
		if err := json.Unmarshal(defJSON, &def); err != nil {
			continue
		}
		actives = append(actives, active{id: id, def: def})
	}
	_ = rows.Err()

	changed := 0
	for _, a := range actives {
		n, err := e.advanceRun(ctx, a.id, &a.def, now)
		if err != nil {
			e.log("advance run", "run", a.id, "error", err)
			continue
		}
		changed += n
	}
	return changed
}

// advanceRun recomputes step statuses for one run and persists changes.
func (e *ScenarioEvaluator) advanceRun(ctx context.Context, runID string, def *ScenarioDef, now time.Time) (int, error) {
	var openedAt time.Time
	if err := e.db.QueryRowContext(ctx,
		`SELECT opened_at FROM scenario_runs WHERE id = ?`, runID).Scan(&openedAt); err != nil {
		return 0, fmt.Errorf("get run: %w", err)
	}
	scope := ""
	_ = e.db.QueryRowContext(ctx, `SELECT scope FROM scenario_runs WHERE id = ?`, runID).Scan(&scope)
	host := strings.TrimPrefix(scope, "host:")

	defJSON, _ := json.Marshal(def)
	available := e.availableSources(ctx, host)

	changed := 0
	for i, tech := range def.ExpectedTechniques {
		status, evidence, conf := e.stepStatus(ctx, def, tech, host, openedAt, now, available)

		var oldStatus sql.NullString
		_ = e.db.QueryRowContext(ctx,
			`SELECT status FROM scenario_steps WHERE run_id = ? AND step_id = ?`, runID, tech).Scan(&oldStatus)
		upserted := oldStatus.Valid && oldStatus.String == status
		if _, err := e.db.ExecContext(ctx,
			`INSERT INTO scenario_steps (run_id, step_id, technique, status, evidence, confidence)
			 VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT(run_id, step_id) DO UPDATE SET
			   status = excluded.status,
			   evidence = excluded.evidence,
			   confidence = excluded.confidence`,
			runID, tech, tech, status, evidence, conf); err != nil {
			return changed, fmt.Errorf("upsert step: %w", err)
		}
		if !upserted {
			changed++
		}
		_ = i
	}

	// Run risk: weighted observed fraction x coverage factor.
	base := 40.0
	if def.Risk == "medium" {
		base = 20.0
	}
	observed := 0
	for _, tech := range def.ExpectedTechniques {
		var st string
		if err := e.db.QueryRowContext(ctx,
			`SELECT status FROM scenario_steps WHERE run_id = ? AND step_id = ?`, runID, tech).Scan(&st); err == nil {
			if st == "observed" {
				observed++
			}
		}
	}
	frac := 0.0
	if len(def.ExpectedTechniques) > 0 {
		frac = float64(observed) / float64(len(def.ExpectedTechniques))
	}
	covFactor := 1.0
	if len(def.RequiredSources) > 0 {
		present := 0
		for _, s := range def.RequiredSources {
			if available[s] {
				present++
			}
		}
		covFactor = float64(present) / float64(len(def.RequiredSources))
	}
	runRisk := base * frac * covFactor
	// Confidence: observed evidence density, bounded.
	runConf := 0.5 * frac
	if runConf > 0.9 {
		runConf = 0.9
	}

	status := "active"
	var closedAt sql.NullTime
	if observed == len(def.ExpectedTechniques) && len(def.ExpectedTechniques) > 0 {
		status = "completed"
		closedAt = sql.NullTime{Time: now, Valid: true}
		e.emitScenarioFinding(ctx, def, runID, host, now)
	} else if now.Sub(openedAt) > 48*time.Hour {
		status = "stale"
		closedAt = sql.NullTime{Time: now, Valid: true}
	}
	if _, err := e.db.ExecContext(ctx,
		`UPDATE scenario_runs SET status = ?, confidence = ?, risk = ?, closed_at = ?, definition = ? WHERE id = ?`,
		status, runConf, runRisk, closedAt, string(defJSON), runID); err != nil {
		return changed, fmt.Errorf("update run: %w", err)
	}
	return changed, nil
}

// stepStatus derives one technique's status for a run (spec §6).
func (e *ScenarioEvaluator) stepStatus(ctx context.Context, def *ScenarioDef, tech, host string, openedAt, now time.Time, available map[string]bool) (string, string, float64) {
	like := "%" + "\"" + tech + "\"" + "%"
	observedIDs, blockedIDs := []string{}, []string{}
	rows, err := e.db.QueryContext(ctx,
		`SELECT id, COALESCE(outcome, '') FROM events
		 WHERE host = ? AND timestamp >= ? AND timestamp <= ?
		   AND json_extract(attributes, '$."mitre"."attack"') LIKE ?`,
		host, openedAt, now, like)
	if err != nil {
		e.log("step events", "tech", tech, "error", err)
		return "unknown", "", 0
	}
	defer rows.Close()
	for rows.Next() {
		var id, outcome string
		if err := rows.Scan(&id, &outcome); err != nil {
			continue
		}
		switch strings.ToLower(outcome) {
		case "failure", "blocked", "denied":
			blockedIDs = append(blockedIDs, id)
		default:
			observedIDs = append(observedIDs, id)
		}
	}
	_ = rows.Err()

	switch {
	case len(observedIDs) > 0:
		return "observed", mustJSON(observedIDs), confidenceFor(len(observedIDs))
	case len(blockedIDs) > 0:
		return "blocked", mustJSON(blockedIDs), confidenceFor(len(blockedIDs))
	}

	// No events. If the telemetry needed to observe this technique is
	// present, absence is evidence it likely did not happen (missing).
	// Otherwise it is unknown — "telemetry insufficient to determine
	// whether ... occurred" (spec §25 verbatim behavior).
	if !e.telemetryCovers(def, tech, available) {
		return "unknown", "telemetry insufficient to determine whether " + tech + " occurred", 0
	}
	// Telemetry present but nothing observed: expected while the run is
	// young, missing once the window has matured.
	if now.Sub(openedAt) < 2*time.Hour {
		return "expected", "", 0
	}
	return "missing", "no evidence within telemetry bounds", 0.6
}

// telemetryCovers reports whether the required source classes for the
// technique are available for the host.
func (e *ScenarioEvaluator) telemetryCovers(def *ScenarioDef, tech string, available map[string]bool) bool {
	// A technique is covered when ANY of the scenario's required sources is
	// available (any of them could surface the technique's evidence).
	if len(def.RequiredSources) == 0 {
		return true
	}
	for _, s := range def.RequiredSources {
		if available[s] {
			return true
		}
	}
	return false
}

// availableSources returns the set of available source classes for a host,
// via the host's asset + telemetry coverage. No asset → empty set (unknown).
func (e *ScenarioEvaluator) availableSources(ctx context.Context, host string) map[string]bool {
	out := map[string]bool{}
	if e.assetStore == nil || e.coverage == nil || host == "" {
		return out
	}
	a, err := e.assetStore.GetByEntityRef(ctx, "host:"+host)
	if err != nil || a == nil {
		return out
	}
	rows, err := e.coverage.Rows(ctx, a.ID)
	if err != nil {
		return out
	}
	for _, r := range rows {
		if r.Available {
			out[r.SourceClass] = true
		}
	}
	return out
}

func (e *ScenarioEvaluator) emitScenarioFinding(ctx context.Context, def *ScenarioDef, runID, host string, now time.Time) {
	// Collect evidence event ids across observed steps.
	rows, err := e.db.QueryContext(ctx,
		`SELECT step_id, evidence FROM scenario_steps WHERE run_id = ? AND status = 'observed'`, runID)
	if err != nil {
		return
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var step, ev string
		if err := rows.Scan(&step, &ev); err != nil {
			continue
		}
		var list []string
		if json.Unmarshal([]byte(ev), &list) == nil {
			ids = append(ids, list...)
		}
	}
	_ = rows.Err()

	title := def.Title + " — " + host
	desc := def.Description + fmt.Sprintf(" (scenario %s, run %s; all %d techniques observed)", def.Name, runID, len(def.ExpectedTechniques))

	// Fetch the evidence events so the finding carries real entities.
	evts := e.eventsByIDs(ctx, ids, 50)

	f, isNew, err := e.findingStore.CreateOrUpdateFromDetection(ctx, findings.FromDetectionArgs{
		RuleID:         "scenario:" + def.Name,
		RuleName:       def.Title,
		GroupKey:       "scenario|" + def.Name + "|" + host,
		Title:          title,
		Description:    desc,
		Severity:       def.Severity,
		DataSource:     "scenario",
		Tags:           []string{"scenario"},
		Matched:        len(ids),
		Events:         evts,
	})
	if err != nil {
		e.log("scenario finding", "error", err)
		return
	}
	if e.logger != nil {
		e.logger("scenario completed", "scenario", def.Name, "host", host, "new", isNew, "finding", f.ID)
	}
}

// eventsByIDs fetches full events for evidence ids (capped).
func (e *ScenarioEvaluator) eventsByIDs(ctx context.Context, ids []string, limit int) []*event.Event {
	out := make([]*event.Event, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] || len(out) >= limit {
			continue
		}
		seen[id] = true
		ev, err := e.evStore.GetByID(ctx, id)
		if err != nil || ev == nil {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// ListRuns lists scenario runs (most recent first).
func (e *ScenarioEvaluator) ListRuns(ctx context.Context, limit int) ([]ScenarioRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := e.db.QueryContext(ctx,
		`SELECT id, definition, scope, status, confidence, risk, opened_at, closed_at
		 FROM scenario_runs ORDER BY opened_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list scenario runs: %w", err)
	}
	defer rows.Close()
	out := []ScenarioRun{}
	for rows.Next() {
		var r ScenarioRun
		var def []byte
		if err := rows.Scan(&r.ID, &def, &r.Scope, &r.Status, &r.Confidence, &r.Risk, &r.OpenedAt, &r.ClosedAt); err != nil {
			return nil, fmt.Errorf("scan scenario run: %w", err)
		}
		r.Definition = json.RawMessage(def)
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRun fetches one run with its steps + what-next.
func (e *ScenarioEvaluator) GetRun(ctx context.Context, id string) (*ScenarioRun, []ScenarioStep, *WhatNext, error) {
	var r ScenarioRun
	var def []byte
	if err := e.db.QueryRowContext(ctx,
		`SELECT id, definition, scope, status, confidence, risk, opened_at, closed_at
		 FROM scenario_runs WHERE id = ?`, id).
		Scan(&r.ID, &def, &r.Scope, &r.Status, &r.Confidence, &r.Risk, &r.OpenedAt, &r.ClosedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil, nil, fmt.Errorf("scenario run %s not found", id)
		}
		return nil, nil, nil, fmt.Errorf("get scenario run: %w", err)
	}
	r.Definition = json.RawMessage(def)
	steps, err := e.Steps(ctx, id)
	if err != nil {
		return nil, nil, nil, err
	}
	wn := &WhatNext{}
	for _, s := range steps {
		switch s.Status {
		case "expected":
			wn.Expected = append(wn.Expected, s)
		case "unknown":
			wn.Unknown = append(wn.Unknown, s)
		}
	}
	return &r, steps, wn, nil
}

// Steps lists the steps of one run.
func (e *ScenarioEvaluator) Steps(ctx context.Context, runID string) ([]ScenarioStep, error) {
	rows, err := e.db.QueryContext(ctx,
		`SELECT run_id, step_id, tactic, technique, status, evidence, confidence
		 FROM scenario_steps WHERE run_id = ? ORDER BY step_id`, runID)
	if err != nil {
		return nil, fmt.Errorf("list scenario steps: %w", err)
	}
	defer rows.Close()
	out := []ScenarioStep{}
	for rows.Next() {
		var s ScenarioStep
		var ev sql.NullString
		var tactic, technique sql.NullString
		var conf sql.NullFloat64
		if err := rows.Scan(&s.RunID, &s.StepID, &tactic, &technique, &s.Status, &ev, &conf); err != nil {
			return nil, fmt.Errorf("scan scenario step: %w", err)
		}
		s.Tactic = tactic.String
		s.Technique = technique.String
		s.Evidence = ev.String
		s.Confidence = conf.Float64
		out = append(out, s)
	}
	return out, rows.Err()
}

func (e *ScenarioEvaluator) log(msg string, kv ...any) {
	if e.logger != nil {
		e.logger(msg, kv...)
	}
}

func confidenceFor(n int) float64 {
	if n <= 1 {
		return 0.6
	}
	c := 0.6 + 0.1*float64(n-1)
	if c > 0.95 {
		return 0.95
	}
	return c
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// yamlUnmarshal decodes a scenario definition file into out.
func yamlUnmarshal(data []byte, out any) error {
	return yaml.Unmarshal(data, out)
}
