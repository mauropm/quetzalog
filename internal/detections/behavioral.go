package detections

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"quetzalog/internal/findings"
	"quetzalog/internal/risk"
	"quetzalog/pkg/event"
)

// Baseline minimums (risk-model.md §5): a feature is only trusted after at
// least minSamples samples over at least minWindowDays. Below that, no
// anomaly score — missing telemetry must never read as "no activity".
const (
	minSamples    = 20
	minWindowDays = 14
	defaultWindow = 30

	// z bands (risk-model.md §5): z>=4 -> 15, z>=3 -> 10, z>=2 -> 5.
	topFeatureWindow = 24 * time.Hour
	noveltyPoints    = 5 // first-seen features: rareness, not malice
	travelSpeedKmh   = 900.0
)

// Baseline is one rolling-stats row.
type Baseline struct {
	EntityType   string  `json:"entity_type"`
	EntityValue  string  `json:"entity_value"`
	Feature      string  `json:"feature"`
	WindowDays   int     `json:"window_days"`
	Mean         float64 `json:"mean"`
	StdDev       float64 `json:"stddev"`
	P95          float64 `json:"p95"`
	SampleCount  int     `json:"sample_count"`
	LastUpdated  time.Time `json:"last_updated"`
}

// IsTrusted reports whether enough history exists to score this feature.
func (b *Baseline) IsTrusted() bool {
	return b.SampleCount >= minSamples && b.WindowDays >= minWindowDays
}

// ZPoints maps a z-score to its risk band.
func ZPoints(z float64) float64 {
	switch {
	case z >= 4:
		return 15
	case z >= 3:
		return 10
	case z >= 2:
		return 5
	default:
		return 0
	}
}

// BaselineUpdater recomputes rolling per-entity baselines from stored events.
// Runs on an hourly ticker (async, off the write path).
type BaselineUpdater struct {
	db     *sql.DB
	logger func(msg string, kv ...any)
}

// NewBaselineUpdater creates the updater.
func NewBaselineUpdater(db *sql.DB, logger func(msg string, kv ...any)) *BaselineUpdater {
	return &BaselineUpdater{db: db, logger: logger}
}

// UpdateAll recomputes the supported features for all active entities.
func (u *BaselineUpdater) UpdateAll(ctx context.Context, now time.Time) error {
	if err := u.updateUserLoginCounts(ctx, now); err != nil {
		return err
	}
	return u.updateBytesPerHour(ctx, now, "host")
}

// updateUserLoginCounts computes user/login_count_per_hour baselines: the
// distribution of hourly authentication-event counts over the window.
func (u *BaselineUpdater) updateUserLoginCounts(ctx context.Context, now time.Time) error {
	users, err := u.activeValues(ctx, now, "user")
	if err != nil {
		return err
	}
	for _, user := range users {
		rows, err := u.db.QueryContext(ctx,
			`SELECT COUNT(*) FROM events
			 WHERE user = ? AND event_type = 'authentication'
			   AND timestamp >= ? AND timestamp <= ?
			 GROUP BY strftime('%Y-%m-%d %H', timestamp)`,
			user, now.Add(-defaultWindow*24*time.Hour), now)
		if err != nil {
			return fmt.Errorf("login counts %s: %w", user, err)
		}
		samples := []float64{}
		for rows.Next() {
			var c int
			if err := rows.Scan(&c); err != nil {
				rows.Close()
				return err
			}
			if c > 0 {
				samples = append(samples, float64(c))
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(samples) == 0 {
			continue
		}
		b := Baseline{
			EntityType:  "user",
			EntityValue: user,
			Feature:     "login_count_per_hour",
			WindowDays:  defaultWindow,
			Mean:        meanOf(samples),
			StdDev:      stdOf(samples),
			P95:         p95Of(samples),
			SampleCount: len(samples),
			LastUpdated: now,
		}
		if err := u.upsert(ctx, b); err != nil {
			return err
		}
	}
	return nil
}

// updateBytesPerHour computes host/bytes_per_hour baselines from the
// `bytes` attribute when present (network telemetry).
func (u *BaselineUpdater) updateBytesPerHour(ctx context.Context, now time.Time, entityField string) error {
	hosts, err := u.activeValues(ctx, now, entityField)
	if err != nil {
		return err
	}
	for _, host := range hosts {
		rows, err := u.db.QueryContext(ctx,
			`SELECT COALESCE(SUM(CAST(json_extract(attributes, '$.bytes') AS INTEGER)), 0)
			 FROM events
			 WHERE host = ? AND json_extract(attributes, '$.bytes') IS NOT NULL
			   AND timestamp >= ? AND timestamp <= ?
			 GROUP BY strftime('%Y-%m-%d %H', timestamp)`,
			host, now.Add(-defaultWindow*24*time.Hour), now)
		if err != nil {
			return fmt.Errorf("bytes %s: %w", host, err)
		}
		samples := []float64{}
		for rows.Next() {
			var c float64
			if err := rows.Scan(&c); err != nil {
				rows.Close()
				return err
			}
			samples = append(samples, c)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(samples) == 0 {
			continue
		}
		b := Baseline{
			EntityType:  "host",
			EntityValue: host,
			Feature:     "bytes_per_hour",
			WindowDays:  defaultWindow,
			Mean:        meanOf(samples),
			StdDev:      stdOf(samples),
			P95:         p95Of(samples),
			SampleCount: len(samples),
			LastUpdated: now,
		}
		if err := u.upsert(ctx, b); err != nil {
			return err
		}
	}
	return nil
}

func (u *BaselineUpdater) activeValues(ctx context.Context, now time.Time, field string) ([]string, error) {
	// Active = seen in the last 7 days (bounds the update cost).
	rows, err := u.db.QueryContext(ctx,
		`SELECT DISTINCT `+field+` FROM events
		 WHERE `+field+` != '' AND timestamp >= ?`,
		now.Add(-7*24*time.Hour))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (u *BaselineUpdater) upsert(ctx context.Context, b Baseline) error {
	_, err := u.db.ExecContext(ctx,
		`INSERT INTO baselines (entity_type, entity_value, feature, window_days, mean, stddev, p95, sample_count, last_updated)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(entity_type, entity_value, feature, window_days) DO UPDATE SET
		   mean = excluded.mean,
		   stddev = excluded.stddev,
		   p95 = excluded.p95,
		   sample_count = excluded.sample_count,
		   last_updated = excluded.last_updated`,
		b.EntityType, b.EntityValue, b.Feature, b.WindowDays, b.Mean, b.StdDev, b.P95, b.SampleCount, b.LastUpdated)
	if err != nil {
		return fmt.Errorf("upsert baseline: %w", err)
	}
	return nil
}

func meanOf(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := 0.0
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}

func stdOf(v []float64) float64 {
	if len(v) < 2 {
		return 0
	}
	m := meanOf(v)
	s := 0.0
	for _, x := range v {
		d := x - m
		s += d * d
	}
	return math.Sqrt(s / float64(len(v)-1))
}

func p95Of(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	sorted := append([]float64(nil), v...)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j] < sorted[i] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	idx := int(math.Ceil(0.95*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// ---------------------------------------------------------------------------
// Behavioral engine
// ---------------------------------------------------------------------------

// behavioralDef is the rule Definition payload for statistical/behavioral
// kinds: either a rolling feature (statistical) or a named pattern
// (behavioral).
type behavioralDef struct {
	Feature string `json:"feature,omitempty"` // login_count_per_hour | bytes_per_hour
	Entity  string `json:"entity,omitempty"`  // user | host (feature dimension)
	Pattern string `json:"pattern,omitempty"` // first-seen-destination | rare-process | impossible-travel
}

// BehavioralEngine evaluates statistical + behavioral rules on the event
// stream (bounded queue, async workers — same contract as the correlation
// engine).
type BehavioralEngine struct {
	db           *sql.DB
	detStore     *Store
	findingStore *findings.Store
	riskStore    *risk.EntityRiskStore
	logger       func(msg string, kv ...any)
	queue        chan *event.Event

	rulesLock sync.RWMutex
	rules     []*DetectionRule
	rulesAt   time.Time

	stopped sync.WaitGroup
}

// NewBehavioralEngine creates the engine.
func NewBehavioralEngine(db *sql.DB, detStore *Store, findingStore *findings.Store, riskStore *risk.EntityRiskStore, logger func(msg string, kv ...any)) *BehavioralEngine {
	return &BehavioralEngine{
		db:           db,
		detStore:     detStore,
		findingStore: findingStore,
		riskStore:    riskStore,
		logger:       logger,
		queue:        make(chan *event.Event, 4096),
	}
}

// Enqueue is the event-store observer hook.
func (e *BehavioralEngine) Enqueue(ev *event.Event) {
	if ev == nil {
		return
	}
	select {
	case e.queue <- ev:
	default:
		if e.logger != nil {
			e.logger("behavioral engine queue full; dropping event", "id", ev.ID)
		}
	}
}

// Start launches the workers.
func (e *BehavioralEngine) Start(workers int) {
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

// Stop closes the queue and waits.
func (e *BehavioralEngine) Stop() {
	close(e.queue)
	e.stopped.Wait()
}

func (e *BehavioralEngine) process(ctx context.Context, ev *event.Event) {
	for _, rule := range e.liveRules(ctx) {
		switch strings.ToLower(rule.Kind) {
		case "statistical":
			e.evalStatistical(ctx, rule, ev)
		case "behavioral":
			e.evalBehavioral(ctx, rule, ev)
		}
	}
}

func (e *BehavioralEngine) liveRules(ctx context.Context) []*DetectionRule {
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
			e.logger("behavioral engine: list rules", "error", err)
		}
		return nil
	}
	out := make([]*DetectionRule, 0, len(all))
	for _, r := range all {
		if !r.Enabled || r.Suppressed {
			continue
		}
		k := strings.ToLower(r.Kind)
		if (k == "statistical" || k == "behavioral") && len(r.Definition) > 0 {
			out = append(out, r)
		}
	}
	e.rulesLock.Lock()
	e.rules = out
	e.rulesAt = time.Now()
	e.rulesLock.Unlock()
	return out
}

// entityForFeature resolves the (type, value) the feature is measured over.
func entityForFeature(def behavioralDef, ev *event.Event) (string, string, bool) {
	switch strings.ToLower(def.Entity) {
	case "host":
		if ev.Host != "" {
			return "host", ev.Host, true
		}
	default: // user (default dimension)
		if ev.User != "" {
			return "user", ev.User, true
		}
	}
	return "", "", false
}

func (e *BehavioralEngine) evalStatistical(ctx context.Context, rule *DetectionRule, ev *event.Event) {
	var def behavioralDef
	if err := json.Unmarshal(rule.Definition, &def); err != nil || def.Feature == "" {
		return
	}
	et, evValue, ok := entityForFeature(def, ev)
	if !ok {
		return
	}

	var observed float64
	var err error
	switch def.Feature {
	case "login_count_per_hour":
		observed, err = e.currentHourCount(ctx, et, evValue, ev.Timestamp, "event_type = 'authentication'")
	case "bytes_per_hour":
		observed, err = e.currentHourBytes(ctx, et, evValue, ev.Timestamp)
	default:
		return
	}
	if err != nil {
		if e.logger != nil {
			e.logger("behavioral observed", "feature", def.Feature, "error", err)
		}
		return
	}

	var b Baseline
	row := e.db.QueryRowContext(ctx,
		`SELECT mean, stddev, p95, sample_count, window_days, last_updated
		 FROM baselines WHERE entity_type = ? AND entity_value = ? AND feature = ? AND window_days = ?`,
		et, evValue, def.Feature, defaultWindow)
	var lastUpdated time.Time
	if err := row.Scan(&b.Mean, &b.StdDev, &b.P95, &b.SampleCount, &b.WindowDays, &lastUpdated); err != nil {
		if err != sql.ErrNoRows {
			e.log("baseline lookup", "error", err)
		}
		return // No baseline yet: unknown, never a negative signal.
	}
	if !b.IsTrusted() {
		return // Below the 20-sample/14-day minimum: no score.
	}

	z := deviationZ(observed, b.Mean, b.StdDev)
	points := ZPoints(z)
	if points <= 0 {
		return
	}

	aID := newID()
	_, err = e.db.ExecContext(ctx,
		`INSERT INTO anomalies (id, entity_type, entity_value, feature, observed, baseline_mean, z, detected_at, detection_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		aID, et, evValue, def.Feature, observed, b.Mean, z, time.Now().UTC(), rule.ID)
	if err != nil {
		e.log("anomaly insert", "error", err)
		return
	}

	// Top-3 features per entity over 24h contribute; the rest stay logged
	// (explainable) but do not add risk points (risk-model.md §5).
	if !e.inTopFeatures(ctx, et, evValue, aID) {
		return
	}

	e.recordAnomalyRisk(ctx, rule, et, evValue, def.Feature, z, points, aID, "")

	// One explainable finding per rule x entity x feature (dedup refresh).
	e.emitAnomalyFinding(ctx, rule, et, evValue, def.Feature, z, observed, b.Mean, ev)
}

// evalBehavioral handles the named behavioral patterns.
func (e *BehavioralEngine) evalBehavioral(ctx context.Context, rule *DetectionRule, ev *event.Event) {
	var def behavioralDef
	if err := json.Unmarshal(rule.Definition, &def); err != nil || def.Pattern == "" {
		return
	}

	switch def.Pattern {
	case "first-seen-destination":
		e.novelty(ctx, rule, ev, "user", ev.User, "ip", ev.DestinationIP, "first_seen_destination")
	case "rare-process":
		e.novelty(ctx, rule, ev, "host", ev.Host, "process", ev.Process, "rare_process")
	case "impossible-travel":
		e.impossibleTravel(ctx, rule, ev)
	}
}

// novelty scores +5 when the referenced entity was first seen within the
// last 24h (novelty != malice, capped at 5 points, risk-model.md §5).
func (e *BehavioralEngine) novelty(ctx context.Context, rule *DetectionRule, ev *event.Event, keyType, keyValue, entType, entValue, feature string) {
	if keyValue == "" || entValue == "" {
		return
	}
	// Dedupe: one novelty score per entity pair per 24h.
	var n int
	_ = e.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM anomalies
		 WHERE entity_type = ? AND entity_value = ? AND feature LIKE ? AND detected_at >= ?`,
		keyType, keyValue, feature+"%", time.Now().UTC().Add(-topFeatureWindow)).Scan(&n)
	if n > 0 {
		return
	}

	var firstSeen time.Time
	err := e.db.QueryRowContext(ctx,
		`SELECT first_seen FROM entities WHERE type = ? AND value = ?`,
		entType, entValue).Scan(&firstSeen)
	if err != nil {
		return // Unknown entity: no claim.
	}
	if time.Since(firstSeen) > topFeatureWindow {
		return
	}

	aID := newID()
	if _, err := e.db.ExecContext(ctx,
		`INSERT INTO anomalies (id, entity_type, entity_value, feature, observed, z, detected_at, detection_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		aID, keyType, keyValue, feature+":"+entValue, 1, 0, time.Now().UTC(), rule.ID); err != nil {
		e.log("novelty anomaly", "error", err)
		return
	}
	e.recordAnomalyRisk(ctx, rule, keyType, keyValue, feature, 0, noveltyPoints, aID, "")
	e.emitAnomalyFinding(ctx, rule, keyType, keyValue, feature+":"+entValue, 0, 1, 0, ev)
}

// impossibleTravel checks the user's previous login location: faster than
// ~900 km/h between two geo-located logins is an anomaly — UNLESS the path
// traverses VPN/proxy infrastructure, in which case it is recorded with 0
// points and suppressed_reason='vpn' (still explainable, risk-model.md §5).
func (e *BehavioralEngine) impossibleTravel(ctx context.Context, rule *DetectionRule, ev *event.Event) {
	if ev.User == "" || ev.EventType != "authentication" {
		return
	}
	lat, lng, ok := geoOf(ev)
	if !ok {
		return // No geo data: unknown, no claim.
	}

	var prevMsg sql.NullString
	err := e.db.QueryRowContext(ctx,
		`SELECT attributes FROM events
		 WHERE user = ? AND event_type = 'authentication' AND timestamp < ?
		 ORDER BY timestamp DESC LIMIT 1`,
		ev.User, ev.Timestamp).Scan(&prevMsg)
	if err != nil || !prevMsg.Valid {
		return
	}
	var prevAttrs map[string]any
	if json.Unmarshal([]byte(prevMsg.String), &prevAttrs) != nil {
		return
	}
	prevLat, prevLng, ok := geoOfAttrs(prevAttrs)
	if !ok {
		return
	}

	hours := ev.Timestamp.Sub(prevEventTime(ctx, e.db, ev.User, ev.Timestamp)).Hours()
	if hours <= 0 {
		return
	}
	speed := haversineKm(lat, lng, prevLat, prevLng) / hours
	if speed <= travelSpeedKmh {
		return
	}

	suppressed := vpnTagged(ev.Attributes) || vpnTagged(prevAttrs)
	points := float64(0)
	reason := ""
	if !suppressed {
		points = ZPoints(4) // travel anomalies are strong signals (z>=4 band)
	} else {
		reason = "vpn"
	}

	aID := newID()
	if _, err := e.db.ExecContext(ctx,
		`INSERT INTO anomalies (id, entity_type, entity_value, feature, observed, z, detected_at, detection_id, suppressed_reason)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		aID, "user", ev.User, "impossible_travel", speed, 4, time.Now().UTC(), rule.ID, reason); err != nil {
		e.log("travel anomaly", "error", err)
		return
	}
	e.recordAnomalyRisk(ctx, rule, "user", ev.User, "impossible_travel", 4, points, aID, reason)
	if !suppressed {
		e.emitAnomalyFinding(ctx, rule, "user", ev.User, "impossible_travel", 4, speed, 0, ev)
	}
}

func (e *BehavioralEngine) inTopFeatures(ctx context.Context, entType, entValue, id string) bool {
	rows, err := e.db.QueryContext(ctx,
		`SELECT id FROM anomalies
		 WHERE entity_type = ? AND entity_value = ? AND detected_at >= ?
		 ORDER BY z DESC, detected_at DESC LIMIT 3`,
		entType, entValue, time.Now().UTC().Add(-topFeatureWindow))
	if err != nil {
		return true // Be conservative: count it.
	}
	defer rows.Close()
	for rows.Next() {
		var topID string
		if err := rows.Scan(&topID); err != nil {
			return true
		}
		if topID == id {
			return true
		}
	}
	return false
}

func (e *BehavioralEngine) recordAnomalyRisk(ctx context.Context, rule *DetectionRule, entType, entValue, feature string, z, points float64, anomalyID, suppressed string) {
	if e.riskStore == nil {
		return
	}
	desc := fmt.Sprintf("behavioral_anomaly %s (z=%.1f)", feature, z)
	if suppressed != "" {
		desc += fmt.Sprintf(" (suppressed: %s)", suppressed)
	}
	_ = e.riskStore.Record(ctx, risk.Contribution{
		EntityType:  entType,
		EntityValue: entValue,
		SourceType:  "anomaly",
		SourceID:    anomalyID,
		Description: desc,
		Points:      points,
	})
}

func (e *BehavioralEngine) emitAnomalyFinding(ctx context.Context, rule *DetectionRule, entType, entValue, feature string, z, observed, baselineMean float64, ev *event.Event) {
	desc := fmt.Sprintf("%s — %s: observed %.1f (baseline mean %.1f, z=%.1f)", rule.Name, feature, observed, baselineMean, z)
	f, isNew, err := e.findingStore.CreateOrUpdateFromDetection(ctx, findings.FromDetectionArgs{
		RuleID:         rule.ID,
		RuleName:       rule.Name,
		GroupKey:       entType + ":" + entValue + "|" + feature,
		Title:          rule.Name,
		Description:    desc,
		Severity:       rule.Severity,
		RiskScore:      rule.RiskScore,
		DataSource:     dataSourceOf(rule),
		MITRETactic:    rule.MITRETactic,
		MITRETechnique: firstOf(rule.MITRETechniques),
		Tags:           rule.Tags,
		Matched:        1,
		Events:         []*event.Event{ev},
	})
	if err != nil {
		e.log("anomaly finding", "error", err)
		return
	}
	if e.logger != nil {
		e.logger("behavioral anomaly", "rule", rule.Name, "feature", feature, "z", z, "new", isNew, "finding", f.ID)
	}
}

// currentHourCount counts matching events in the current hour for the entity.
func (e *BehavioralEngine) currentHourCount(ctx context.Context, entType, entValue string, ts time.Time, where string) (float64, error) {
	hourStart := ts.Truncate(time.Hour)
	field := "user"
	if entType == "host" {
		field = "host"
	}
	var c int
	err := e.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM events WHERE `+field+` = ? AND `+where+
			` AND timestamp >= ? AND timestamp <= ?`,
		entValue, hourStart, time.Now().UTC()).Scan(&c)
	if err != nil {
		return 0, err
	}
	return float64(c), nil
}

// currentHourBytes sums the bytes attribute for the entity's current hour.
func (e *BehavioralEngine) currentHourBytes(ctx context.Context, entType, entValue string, ts time.Time) (float64, error) {
	hourStart := ts.Truncate(time.Hour)
	field := "user"
	if entType == "host" {
		field = "host"
	}
	var sum float64
	err := e.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(CAST(json_extract(attributes, '$.bytes') AS REAL)), 0)
		 FROM events WHERE `+field+` = ?
		   AND json_extract(attributes, '$.bytes') IS NOT NULL
		   AND timestamp >= ? AND timestamp <= ?`,
		entValue, hourStart, time.Now().UTC()).Scan(&sum)
	if err != nil {
		return 0, err
	}
	return sum, nil
}

// deviationZ computes |observed-mean|/stddev with a documented convention
// for zero-variance baselines (constant history): any observation above the
// (single) mean is treated as a strong deviation.
func deviationZ(observed, mean, stddev float64) float64 {
	if observed < mean {
		observed = mean // only upward deviations matter for these features
	}
	if stddev < 1e-9 {
		if observed > mean+1e-9 {
			return 4
		}
		return 0
	}
	return (observed - mean) / stddev
}

// ---------------------------------------------------------------------------
// Geo helpers
// ---------------------------------------------------------------------------

func geoOf(ev *event.Event) (float64, float64, bool) {
	if ev.Attributes == nil {
		return 0, 0, false
	}
	return geoOfAttrs(ev.Attributes)
}

func geoOfAttrs(attrs map[string]any) (float64, float64, bool) {
	lat, ok1 := parseFloatAttr(attrs, "geo.latitude")
	lng, ok2 := parseFloatAttr(attrs, "geo.longitude")
	if !ok1 || !ok2 {
		return 0, 0, false
	}
	return lat, lng, true
}

func parseFloatAttr(attrs map[string]any, key string) (float64, bool) {
	v, ok := attrs[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case string:
		var f float64
		if _, err := fmt.Sscanf(n, "%f", &f); err == nil {
			return f, true
		}
	}
	return 0, false
}

// vpnTagged reports whether the event carries a VPN/proxy network tag.
func vpnTagged(attrs map[string]any) bool {
	for _, key := range []string{"network.vpn", "network.proxy"} {
		if _, ok := attrs[key]; ok {
			if b, ok2 := attrs[key].(bool); ok2 && !b {
				continue
			}
			return true
		}
	}
	return false
}

// prevEventTime returns the timestamp of the user's previous authentication
// event before the given time.
func prevEventTime(ctx context.Context, db *sql.DB, user string, before time.Time) time.Time {
	var ts time.Time
	if err := db.QueryRowContext(ctx,
		`SELECT timestamp FROM events WHERE user = ? AND event_type = 'authentication' AND timestamp < ?
		 ORDER BY timestamp DESC LIMIT 1`, user, before).Scan(&ts); err != nil {
		return time.Time{}
	}
	return ts
}

// haversineKm is the great-circle distance in kilometers.
func haversineKm(lat1, lon1, lat2, lon2 float64) float64 {
	const r = 6371.0
	toRad := func(d float64) float64 { return d * math.Pi / 180 }
	dLat := toRad(lat2 - lat1)
	dLon := toRad(lon2 - lon1)
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(toRad(lat1))*math.Cos(toRad(lat2))*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * r * math.Asin(math.Sqrt(a))
}

// newID returns a random id (no uuid dependency in this file).
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("an-%d", time.Now().UnixNano())
	}
	const hex = "0123456789abcdef"
	out := make([]byte, 32)
	for i, c := range b {
		out[i*2] = hex[c>>4]
		out[i*2+1] = hex[c&0xF]
	}
	return string(out)
}

func (e *BehavioralEngine) log(msg string, kv ...any) {
	if e.logger != nil {
		e.logger(msg, kv...)
	}
}
