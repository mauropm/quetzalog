package detections

import (
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"quetzalog/internal/events"
	"quetzalog/internal/findings"
	"quetzalog/internal/risk"
	"quetzalog/pkg/event"
)

const (
	// seqBufferCap caps out-of-order events kept per sequence state (spec §2).
	seqBufferCap = 20
	// corrBufferCap caps windowed events kept per correlation state.
	corrBufferCap = 500
	// ruleCacheTTL bounds how stale the rule list may be in the hot path.
	ruleCacheTTL = 30 * time.Second
)

// CorrelationState is one persisted row of correlation_state.
type CorrelationState struct {
	RuleID         string          `json:"rule_id"`
	StateKey       string          `json:"state_key"`
	CurrentStep    int             `json:"current_step"`
	StepFirstEvent string          `json:"step_first_event,omitempty"`
	LastEventAt    time.Time       `json:"last_event_at"`
	Evidence       json.RawMessage `json:"evidence"`
	ExpiresAt      time.Time       `json:"expires_at"`
}

// sequenceDef is the rule Definition payload for kind=sequence.
type sequenceDef struct {
	CorrelationKey []string       `json:"correlation_key"`
	Window         string         `json:"window"`
	MaxGap         string         `json:"max_gap"`
	Steps          []sequenceStep `json:"steps"`
}

type sequenceStep struct {
	ID        string            `json:"id"`
	Predicate map[string]string `json:"predicate"`
	Technique string            `json:"technique,omitempty"`
}

// correlationDef is the rule Definition payload for kind=correlation.
type correlationDef struct {
	CorrelationKey []string        `json:"correlation_key"`
	Window         string          `json:"window"`
	Require        string          `json:"require"` // "all" (default) | "most"
	MinMatch       int             `json:"min_match"`
	Conditions     []corrCondition `json:"conditions"`
	Techniques     []string        `json:"techniques,omitempty"`
}

type corrCondition struct {
	ID        string            `json:"id"`
	Predicate map[string]string `json:"predicate"`
	CountGTE  int               `json:"count_gte"`
}

// seqEntry is one buffered event in a sequence state.
type seqEntry struct {
	ts   time.Time
	step int
	ev   *event.Event
}

// corrEntry is one buffered event in a correlation state.
type corrEntry struct {
	ts time.Time
	ev *event.Event
}

type seqState struct {
	progress int
	buf      []seqEntry
	updated  time.Time
}

type corrState struct {
	buf []corrEntry
}

// CorrelationEngine evaluates sequence + correlation rules on the event
// stream. The observer hook (Enqueue) is bounded and non-blocking; all
// evaluation happens in async workers, never on the ingestion write path.
type CorrelationEngine struct {
	db           *sql.DB
	detStore     *Store
	evStore      *events.Store
	findingStore *findings.Store
	riskStore    *risk.EntityRiskStore
	logger       func(msg string, kv ...any)
	queue        chan *event.Event

	mu        sync.Mutex
	byKey     map[string]any // "seq|rule|<key>" / "corr|rule|<key>" -> state
	rulesLock sync.RWMutex
	rules     []*DetectionRule
	rulesAt   time.Time

	stopped sync.WaitGroup
}

// NewCorrelationEngine creates the engine. All stores share the database.
func NewCorrelationEngine(db *sql.DB, detStore *Store, evStore *events.Store, findingStore *findings.Store, riskStore *risk.EntityRiskStore, logger func(msg string, kv ...any)) *CorrelationEngine {
	return &CorrelationEngine{
		db:           db,
		detStore:     detStore,
		evStore:      evStore,
		findingStore: findingStore,
		riskStore:    riskStore,
		logger:       logger,
		queue:        make(chan *event.Event, 4096),
		byKey:        map[string]any{},
	}
}

// Enqueue is the event-store observer hook: bounded, non-blocking.
func (e *CorrelationEngine) Enqueue(ev *event.Event) {
	if ev == nil {
		return
	}
	select {
	case e.queue <- ev:
	default:
		if e.logger != nil {
			e.logger("correlation engine queue full; dropping event", "id", ev.ID)
		}
	}
}

// Start launches the evaluation workers.
func (e *CorrelationEngine) Start(workers int) {
	if workers <= 0 {
		workers = 2
	}
	for i := 0; i < workers; i++ {
		e.stopped.Add(1)
		go func() {
			defer e.stopped.Done()
			for ev := range e.queue {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				e.process(ctx, ev)
				cancel()
			}
		}()
	}
}

// Stop drains and closes the queue.
func (e *CorrelationEngine) Stop() {
	close(e.queue)
	e.stopped.Wait()
}

// liveRules returns enabled, non-suppressed sequence/correlation rules,
// re-read from the database at most every ruleCacheTTL.
func (e *CorrelationEngine) liveRules(ctx context.Context) []*DetectionRule {
	e.rulesLock.RLock()
	fresh := time.Since(e.rulesAt) < ruleCacheTTL
	rules := e.rules
	e.rulesLock.RUnlock()
	if fresh {
		return rules
	}

	all, err := e.detStore.List(ctx)
	if err != nil {
		if e.logger != nil {
			e.logger("correlation engine: list rules", "error", err)
		}
		return nil
	}
	out := make([]*DetectionRule, 0, len(all))
	for _, r := range all {
		if !r.Enabled || r.Suppressed {
			continue
		}
		k := strings.ToLower(r.Kind)
		if (k == "sequence" || k == "correlation") && len(r.Definition) > 0 {
			out = append(out, r)
		}
	}
	e.rulesLock.Lock()
	e.rules = out
	e.rulesAt = time.Now()
	e.rulesLock.Unlock()
	return out
}

func (e *CorrelationEngine) process(ctx context.Context, ev *event.Event) {
	rules := e.liveRules(ctx)
	if len(rules) == 0 {
		return
	}
	for _, rule := range rules {
		switch strings.ToLower(rule.Kind) {
		case "sequence":
			e.evalSequence(ctx, rule, ev)
		case "correlation":
			e.evalCorrelation(ctx, rule, ev)
		}
	}
}

// keyValues extracts the correlation-key field values from an event.
// ok=false when any key field is empty (the event cannot participate in
// correlation for that key).
func keyValues(keyFields []string, ev *event.Event) ([]string, bool) {
	vals := make([]string, 0, len(keyFields))
	for _, f := range keyFields {
		v := eventFieldValue(f, ev)
		if strings.TrimSpace(v) == "" {
			return nil, false
		}
		vals = append(vals, v)
	}
	return vals, true
}

// eventFieldValue resolves a field name to an event value.
func eventFieldValue(field string, ev *event.Event) string {
	switch strings.ToLower(strings.TrimSpace(field)) {
	case "source_type", "sourcetype", "source":
		if ev.SourceType != "" {
			return ev.SourceType
		}
		return ev.Source
	case "event_type", "eventtype":
		return ev.EventType
	case "category":
		return ev.Category
	case "action":
		return ev.Action
	case "outcome":
		return ev.Outcome
	case "user":
		return ev.User
	case "host":
		return ev.Host
	case "process":
		return ev.Process
	case "service":
		return ev.Service
	case "severity", "sev":
		return ev.Severity
	case "source_ip", "src_ip":
		return ev.SourceIP
	case "destination_ip", "dest_ip":
		return ev.DestinationIP
	}
	if ev.Attributes != nil {
		if v, ok := ev.Attributes[strings.ToLower(field)]; ok {
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}

// predicateMatches checks a map predicate (field → value, case-insensitive
// equality) against an event. Empty/nil predicates match everything.
func predicateMatches(pred map[string]string, ev *event.Event) bool {
	for k, want := range pred {
		if !strings.EqualFold(eventFieldValue(k, ev), want) {
			return false
		}
	}
	return true
}

func stateKeyFor(ruleID string, vals []string) string {
	h := sha1.New()
	fmt.Fprintf(h, "%s\x00%s", ruleID, strings.Join(vals, "\x00"))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func parseRuleWindow(s string) time.Duration {
	if s == "" {
		return time.Hour
	}
	if d, err := parseDetectionWindow(s); err == nil && d > 0 {
		return d
	}
	return time.Hour
}

// ---------------------------------------------------------------------------
// Sequence rules
// ---------------------------------------------------------------------------

func (e *CorrelationEngine) evalSequence(ctx context.Context, rule *DetectionRule, ev *event.Event) {
	var def sequenceDef
	if err := json.Unmarshal(rule.Definition, &def); err != nil {
		return
	}
	if len(def.Steps) == 0 || len(def.CorrelationKey) == 0 {
		return
	}

	vals, ok := keyValues(def.CorrelationKey, ev)
	if !ok {
		return
	}
	key := stateKeyFor(rule.ID, vals)
	memKey := "seq|rule|" + key

	// Find which step (if any) this event satisfies.
	matchedStep := -1
	for i, step := range def.Steps {
		if predicateMatches(step.Predicate, ev) {
			matchedStep = i
			break
		}
	}

	window := parseRuleWindow(def.Window)
	now := time.Now().UTC()

	e.mu.Lock()
	st, _ := e.byKey[memKey].(*seqState)
	if st == nil {
		st = &seqState{}
		e.byKey[memKey] = st
	}
	// Expired state: drop progress.
	if !st.updated.IsZero() && now.After(st.updated.Add(window)) {
		st.progress = 0
		st.buf = nil
	}
	if matchedStep >= 0 {
		st.buf = append(st.buf, seqEntry{ts: ev.Timestamp, step: matchedStep, ev: ev})
		if len(st.buf) > seqBufferCap {
			st.buf = st.buf[len(st.buf)-seqBufferCap:]
		}
		// Expiry is measured from the last step-matching event.
		st.updated = now
	}
	e.mu.Unlock()

	if len(st.buf) == 0 {
		return
	}

	// Greedy in-order chain over the buffered events (handles out-of-order
	// arrivals up to the buffer cap; respects max_gap between steps).
	sort.Slice(st.buf, func(i, j int) bool { return st.buf[i].ts.Before(st.buf[j].ts) })
	maxGap := time.Duration(0)
	if def.MaxGap != "" {
		maxGap, _ = parseDetectionWindow(def.MaxGap)
	}
	idx := 0
	chain := make([]*event.Event, 0, len(def.Steps))
	var last time.Time
	for _, ent := range st.buf {
		if ent.step != idx {
			continue
		}
		if !last.IsZero() && maxGap > 0 && ent.ts.Sub(last) > maxGap {
			continue
		}
		chain = append(chain, ent.ev)
		last = ent.ts
		idx++
		if idx == len(def.Steps) {
			break
		}
	}
	st.progress = idx

	// Persist state bookkeeping (evidence = buffered event ids per step).
	evidence := make([]map[string]any, 0, len(st.buf))
	for _, ent := range st.buf {
		evidence = append(evidence, map[string]any{
			"ts":   ent.ts.UTC().Format(time.RFC3339),
			"id":   ent.ev.ID,
			"step": ent.step,
		})
	}
	var firstEvent, lastAt string
	if len(st.buf) > 0 {
		firstEvent = st.buf[0].ev.ID
		lastAt = st.buf[len(st.buf)-1].ts.UTC().Format(time.RFC3339)
	}
	_ = e.persistState(ctx, rule.ID, key, idx, firstEvent, lastAt, evidence, window)

	if idx < len(def.Steps) {
		return
	}

	// Full chain matched: materialize a finding, then reset the state.
	techniques := []string{}
	for _, s := range def.Steps {
		if s.Technique != "" {
			techniques = append(techniques, s.Technique)
		}
	}
	e.emitSequenceFinding(ctx, rule, key, chain, techniques)

	e.mu.Lock()
	delete(e.byKey, memKey)
	e.mu.Unlock()
	_ = e.deleteState(ctx, rule.ID, key)
}

func (e *CorrelationEngine) emitSequenceFinding(ctx context.Context, rule *DetectionRule, key string, chain []*event.Event, techniques []string) {
	desc := rule.Description
	if len(techniques) > 0 {
		desc += " (sequence " + strings.Join(techniques, " → ") + ")"
	}
	f, isNew, err := e.findingStore.CreateOrUpdateFromDetection(ctx, findings.FromDetectionArgs{
		RuleID:         rule.ID,
		RuleName:       rule.Name,
		GroupKey:       key,
		Title:          rule.Name,
		Description:    desc,
		Severity:       rule.Severity,
		RiskScore:      rule.RiskScore,
		DataSource:     dataSourceOf(rule),
		MITRETactic:    rule.MITRETactic,
		MITRETechnique: firstOf(techniques),
		Tags:           rule.Tags,
		Matched:        len(chain),
		Events:         chain,
	})
	if err != nil {
		if e.logger != nil {
			e.logger("sequence finding", "rule", rule.Name, "error", err)
		}
		return
	}
	if e.logger != nil {
		e.logger("sequence match", "rule", rule.Name, "key", key, "new", isNew, "finding", f.ID)
	}
	if isNew && e.riskStore != nil && f.RiskScore > 0 {
		recordFindingRisk(ctx, e.riskStore, f)
	}
}

// ---------------------------------------------------------------------------
// Correlation rules
// ---------------------------------------------------------------------------

func (e *CorrelationEngine) evalCorrelation(ctx context.Context, rule *DetectionRule, ev *event.Event) {
	var def correlationDef
	if err := json.Unmarshal(rule.Definition, &def); err != nil {
		return
	}
	if len(def.Conditions) == 0 || len(def.CorrelationKey) == 0 {
		return
	}

	vals, ok := keyValues(def.CorrelationKey, ev)
	if !ok {
		return
	}
	key := stateKeyFor(rule.ID, vals)
	memKey := "corr|rule|" + key

	window := parseRuleWindow(def.Window)
	now := time.Now().UTC()

	anyMatch := false
	for _, c := range def.Conditions {
		if predicateMatches(c.Predicate, ev) {
			anyMatch = true
			break
		}
	}

	e.mu.Lock()
	st, _ := e.byKey[memKey].(*corrState)
	if st == nil {
		st = &corrState{}
		e.byKey[memKey] = st
	}
	// Evict events outside the window.
	cutoff := now.Add(-window)
	kept := st.buf[:0]
	for _, ent := range st.buf {
		if !ent.ts.Before(cutoff) {
			kept = append(kept, ent)
		}
	}
	st.buf = kept
	if anyMatch {
		st.buf = append(st.buf, corrEntry{ts: ev.Timestamp, ev: ev})
		if len(st.buf) > corrBufferCap {
			st.buf = st.buf[len(st.buf)-corrBufferCap:]
		}
	}
	e.mu.Unlock()

	if len(st.buf) == 0 {
		return
	}

	// Per-condition counts over the window.
	satisfied := make([]string, 0, len(def.Conditions))
	for _, c := range def.Conditions {
		need := c.CountGTE
		if need <= 0 {
			need = 1
		}
		n := 0
		for _, ent := range st.buf {
			if predicateMatches(c.Predicate, ent.ev) {
				n++
			}
		}
		if n >= need {
			satisfied = append(satisfied, c.ID)
		}
	}

	required := len(def.Conditions)
	if strings.EqualFold(def.Require, "most") {
		required = def.MinMatch
		if required <= 0 {
			required = len(def.Conditions) - 1
		}
		if required > len(def.Conditions) {
			required = len(def.Conditions)
		}
	}
	if len(satisfied) < required {
		// Keep bookkeeping visible while conditions are still pending.
		lastAt := ""
		if len(st.buf) > 0 {
			lastAt = st.buf[len(st.buf)-1].ts.UTC().Format(time.RFC3339)
		}
		_ = e.persistState(ctx, rule.ID, key, 0, "", lastAt, map[string]any{
			"satisfied": satisfied,
			"pending":   len(def.Conditions) - len(satisfied),
		}, window)
		return
	}

	// All required conditions met: emit once per episode, then reset.
	base := rule.Confidence
	if base <= 0 {
		base = 0.7
	}
	conf := base + 0.05*float64(len(satisfied)-required)
	if conf > 0.95 {
		conf = 0.95
	}

	groupKey := key + "|" + strings.Join(satisfied, ",")
	evts := make([]*event.Event, 0, len(st.buf))
	for _, ent := range st.buf {
		evts = append(evts, ent.ev)
	}
	f, isNew, err := e.findingStore.CreateOrUpdateFromDetection(ctx, findings.FromDetectionArgs{
		RuleID:         rule.ID,
		RuleName:       rule.Name,
		GroupKey:       groupKey,
		Title:          rule.Name,
		Description:    rule.Description + fmt.Sprintf(" (correlation: %d/%d conditions satisfied, confidence %.2f)", len(satisfied), len(def.Conditions), conf),
		Severity:       rule.Severity,
		RiskScore:      rule.RiskScore,
		DataSource:     dataSourceOf(rule),
		MITRETactic:    rule.MITRETactic,
		MITRETechnique: firstOf(def.Techniques),
		Tags:           rule.Tags,
		Matched:        len(evts),
		Events:         evts,
	})
	if err != nil {
		if e.logger != nil {
			e.logger("correlation finding", "rule", rule.Name, "error", err)
		}
		return
	}
	if e.logger != nil {
		e.logger("correlation match", "rule", rule.Name, "key", key, "satisfied", len(satisfied), "confidence", conf, "new", isNew)
	}
	if isNew && e.riskStore != nil && f.RiskScore > 0 {
		recordFindingRisk(ctx, e.riskStore, f)
	}

	e.mu.Lock()
	delete(e.byKey, memKey)
	e.mu.Unlock()
	_ = e.deleteState(ctx, rule.ID, key)
}

// ---------------------------------------------------------------------------
// State persistence
// ---------------------------------------------------------------------------

func (e *CorrelationEngine) persistState(ctx context.Context, ruleID, key string, step int, firstEvent, lastAt string, evidence any, window time.Duration) error {
	evJSON, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	lastT := time.Now().UTC()
	if lastAt != "" {
		if t, perr := time.Parse(time.RFC3339, lastAt); perr == nil {
			lastT = t
		}
	}
	_, err = e.db.ExecContext(ctx,
		`INSERT INTO correlation_state (rule_id, state_key, current_step, step_first_event, last_event_at, evidence, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(rule_id, state_key) DO UPDATE SET
		   current_step = excluded.current_step,
		   step_first_event = excluded.step_first_event,
		   last_event_at = excluded.last_event_at,
		   evidence = excluded.evidence,
		   expires_at = excluded.expires_at`,
		ruleID, key, step, firstEvent, lastT, string(evJSON), lastT.Add(window))
	if err != nil {
		return fmt.Errorf("persist correlation state: %w", err)
	}
	return nil
}

func (e *CorrelationEngine) deleteState(ctx context.Context, ruleID, key string) error {
	_, err := e.db.ExecContext(ctx,
		`DELETE FROM correlation_state WHERE rule_id = ? AND state_key = ?`, ruleID, key)
	if err != nil {
		return fmt.Errorf("delete correlation state: %w", err)
	}
	return nil
}

// Sweep prunes expired correlation states (safety net; the engine also
// drops expired sequence state lazily on the hot path).
func (e *CorrelationEngine) Sweep(ctx context.Context) (int, error) {
	res, err := e.db.ExecContext(ctx,
		`DELETE FROM correlation_state WHERE expires_at < ?`, time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("sweep correlation state: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ListStates returns the persisted states for one rule (debuggability:
// a stuck sequence must be inspectable, spec §2).
func (e *CorrelationEngine) ListStates(ctx context.Context, ruleID string) ([]CorrelationState, error) {
	rows, err := e.db.QueryContext(ctx,
		`SELECT rule_id, state_key, current_step, step_first_event, last_event_at, evidence, expires_at
		 FROM correlation_state WHERE rule_id = ? ORDER BY last_event_at DESC LIMIT 500`, ruleID)
	if err != nil {
		return nil, fmt.Errorf("list correlation states: %w", err)
	}
	defer rows.Close()
	out := []CorrelationState{}
	for rows.Next() {
		var s CorrelationState
		var ev sql.NullString
		var first sql.NullString
		if err := rows.Scan(&s.RuleID, &s.StateKey, &s.CurrentStep, &first, &s.LastEventAt, &ev, &s.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scan correlation state: %w", err)
		}
		s.StepFirstEvent = first.String
		s.Evidence = json.RawMessage(ev.String)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate correlation states: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func dataSourceOf(rule *DetectionRule) string {
	if len(rule.DataSources) > 0 {
		return rule.DataSources[0]
	}
	return ""
}

func firstOf(list []string) string {
	if len(list) == 0 {
		return ""
	}
	return list[0]
}

// recordFindingRisk records the finding's risk contributions for its
// entities (same semantics as the threshold engine).
func recordFindingRisk(ctx context.Context, rs *risk.EntityRiskStore, f *findings.Finding) {
	for _, ent := range f.Entities {
		parts := strings.SplitN(ent, ":", 2)
		if len(parts) != 2 || parts[1] == "" {
			continue
		}
		et, ev := parts[0], parts[1]
		points := f.RiskScore
		if et == "process" {
			points = f.RiskScore / 2
		}
		_ = rs.Record(ctx, risk.Contribution{
			EntityType:  et,
			EntityValue: ev,
			SourceType:  "finding",
			SourceID:    f.ID,
			Description: fmt.Sprintf("%s (%s)", f.Title, f.Severity),
			Points:      points,
		})
	}
}
