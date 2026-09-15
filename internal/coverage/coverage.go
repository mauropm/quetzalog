// Package coverage computes telemetry coverage per asset: which source
// classes actually emit events for an asset, how fresh the telemetry is,
// and which expected classes are absent.
//
// The invariant (docs/telemetry-coverage.md §1): missing telemetry yields
// "unknown" + coverage "missing" — never a negative claim. Coverage is
// observed from the event stream, not declared by agents.
package coverage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"quetzalog/internal/assets"
	"quetzalog/internal/normalization"
	"quetzalog/pkg/event"
)

// Row is one asset × source-class telemetry record.
type Row struct {
	AssetID       string     `json:"asset_id"`
	SourceClass   string     `json:"source_class"`
	Available     bool       `json:"available"`
	LastEvent     *time.Time `json:"last_event,omitempty"`
	EventCount30d int        `json:"event_count_30d"`
	Expected      bool       `json:"expected"`
	Collector     string     `json:"collector,omitempty"`
}

// Coverage is the computed result for one asset.
type Coverage struct {
	AssetID     string    `json:"asset_id"`
	AssetName   string    `json:"asset_name"`
	EntityType  string    `json:"entity_type"`
	OS          string    `json:"os,omitempty"`
	CoveragePct float64   `json:"coverage_pct"`
	Weighted    int       `json:"weighted_classes"`
	Available   []string  `json:"available,omitempty"`
	Missing     []string  `json:"missing,omitempty"`
	Stale       []string  `json:"stale,omitempty"`
	Unexpected  []string  `json:"unexpected,omitempty"`
	ComputedAt  time.Time `json:"computed_at"`
}

// Store persists asset_telemetry rows.
type Store struct {
	db *sql.DB
}

// NewStore creates a coverage store.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

// Upsert records the observed state of one asset × class.
func (s *Store) Upsert(ctx context.Context, r Row) error {
	avail := 0
	if r.Available {
		avail = 1
	}
	exp := 0
	if r.Expected {
		exp = 1
	}
	var lastEvent any
	if r.LastEvent != nil {
		lastEvent = *r.LastEvent
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO asset_telemetry (asset_id, source_class, available, last_event, event_count_30d, expected, collector)
		VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(asset_id, source_class) DO UPDATE SET
			available = excluded.available,
			last_event = CASE
				WHEN excluded.last_event IS NULL THEN asset_telemetry.last_event
				WHEN asset_telemetry.last_event IS NULL THEN excluded.last_event
				WHEN asset_telemetry.last_event > excluded.last_event THEN asset_telemetry.last_event
				ELSE excluded.last_event
			END,
			event_count_30d = excluded.event_count_30d,
			expected = MAX(excluded.expected, asset_telemetry.expected),
			collector = COALESCE(NULLIF(excluded.collector,''), asset_telemetry.collector)`,
		r.AssetID, r.SourceClass, avail, lastEvent, r.EventCount30d, exp, nullStr(r.Collector))
	if err != nil {
		return fmt.Errorf("upsert asset telemetry: %w", err)
	}
	return nil
}

// Rows returns the stored telemetry rows for an asset.
func (s *Store) Rows(ctx context.Context, assetID string) ([]Row, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT asset_id, source_class, available, last_event, event_count_30d, expected, collector
		FROM asset_telemetry WHERE asset_id = ? ORDER BY source_class`, assetID)
	if err != nil {
		return nil, fmt.Errorf("query asset telemetry: %w", err)
	}
	defer rows.Close()
	out := []Row{}
	for rows.Next() {
		var r Row
		var avail, exp int
		var last sql.NullTime
		var col sql.NullString
		if err := rows.Scan(&r.AssetID, &r.SourceClass, &avail, &last, &r.EventCount30d, &exp, &col); err != nil {
			return nil, err
		}
		r.Available = avail != 0
		r.Expected = exp != 0
		r.Collector = col.String
		if last.Valid {
			ts := last.Time
			r.LastEvent = &ts
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// MarkExpected records an analyst declaration that a class is expected.
func (s *Store) MarkExpected(ctx context.Context, assetID, class string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO asset_telemetry (asset_id, source_class, available, event_count_30d, expected)
		VALUES (?, ?, 0, 0, 1)
		ON CONFLICT(asset_id, source_class) DO UPDATE SET expected = 1`, assetID, class)
	if err != nil {
		return fmt.Errorf("mark expected: %w", err)
	}
	return nil
}

// WeightsFor returns the source-class weights for an asset's platform.
// Unknown platforms yield an empty set: no weights, no coverage claim
// (an honest "unknown" beats a fabricated percentage).
func WeightsFor(entityType, os string) map[string]float64 {
	platform := ""
	if strings.Contains(strings.ToLower(os), "windows") {
		platform = "windows"
	} else if entityType != "" {
		switch entityType {
		case "network":
			platform = "network"
		case "database", "application":
			platform = "linux"
		}
	}
	if platform == "" && strings.Contains(strings.ToLower(os), "linux") {
		platform = "linux"
	}
	if platform == "" {
		// A host without OS info: use the linux set when the entity type is
		// host-ish, otherwise no weights at all.
		switch entityType {
		case "host", "server", "workstation", "container":
			platform = "linux"
		}
	}
	switch platform {
	case "windows":
		return map[string]float64{
			normalization.ClassWinSecurity:   0.28,
			normalization.ClassWinSysmon:     0.27,
			normalization.ClassWinPowerShell: 0.17,
			normalization.ClassWinDefender:   0.11,
			normalization.ClassWinDNS:        0.05,
			normalization.ClassNetFlow:       0.12,
		}
	case "linux":
		return map[string]float64{
			normalization.ClassLinuxAuditd:  0.30,
			normalization.ClassLinuxSSHD:    0.15,
			normalization.ClassLinuxSudo:    0.10,
			normalization.ClassLinuxJournal: 0.15,
			normalization.ClassNetFlow:      0.15,
			normalization.ClassNetDNS:       0.15,
		}
	case "network":
		return map[string]float64{
			normalization.ClassNetFirewall: 0.40,
			normalization.ClassNetDNS:      0.20,
			normalization.ClassNetFlow:     0.20,
			normalization.ClassNetIDS:      0.20,
		}
	}
	return nil
}

// EventClassFor derives the source class of an event. Only an explicit
// "source_class" attribute (validated against the taxonomy) is trusted;
// transport-level source types have no inherent telemetry concern and
// resolve to the generic class, which never satisfies a specific weight.
func EventClassFor(ev *event.Event) string {
	if ev == nil || ev.Attributes == nil {
		return normalization.ClassGeneric
	}
	if c, ok := ev.Attributes["source_class"].(string); ok {
		return normalization.ClassFor(c)
	}
	return normalization.ClassGeneric
}

// Runner computes coverage for assets on demand or on a schedule.
type Runner struct {
	db        *sql.DB
	assets    *assets.Store
	store     *Store
	logger    *slog.Logger
	freshness time.Duration
}

// NewRunner creates a coverage runner.
func NewRunner(db *sql.DB, assetStore *assets.Store, store *Store, logger *slog.Logger, freshness time.Duration) *Runner {
	if logger == nil {
		logger = slog.Default()
	}
	if freshness <= 0 {
		freshness = 24 * time.Hour
	}
	return &Runner{db: db, assets: assetStore, store: store, logger: logger, freshness: freshness}
}

// maxEventsPerAsset bounds the per-asset event scan.
const maxEventsPerAsset = 20000

// window is the lookback used for availability counts.
const window = 30 * 24 * time.Hour

// CoverageFor computes coverage on demand for one asset.
func (r *Runner) CoverageFor(ctx context.Context, assetID string) (*Coverage, error) {
	a, err := r.assets.Get(ctx, assetID)
	if err != nil {
		return nil, err
	}
	cov := &Coverage{
		AssetID:    a.ID,
		AssetName:  a.Name,
		EntityType: a.EntityType,
		OS:         a.OS,
		ComputedAt: time.Now().UTC(),
		Weighted:   len(WeightsFor(a.EntityType, a.OS)),
	}
	weights := WeightsFor(a.EntityType, a.OS)
	if len(weights) == 0 {
		return cov, nil
	}

	observed, err := r.observeClasses(ctx, a.EntityRef)
	if err != nil {
		return nil, err
	}
	totalWeight := 0.0
	for _, w := range weights {
		totalWeight += w
	}
	availableWeight := 0.0
	for c, w := range weights {
		if st, ok := observed[c]; ok && st.lastEvent.After(time.Time{}) {
			availableWeight += w
			cov.Available = append(cov.Available, c)
			if time.Since(st.lastEvent) > r.freshness {
				cov.Stale = append(cov.Stale, c)
			}
		} else {
			cov.Missing = append(cov.Missing, c)
		}
	}
	for c := range observed {
		if _, ok := weights[c]; !ok {
			cov.Unexpected = append(cov.Unexpected, c)
		}
	}
	if totalWeight > 0 {
		cov.CoveragePct = round2(availableWeight / totalWeight * 100)
	}
	return cov, nil
}

type classState struct {
	lastEvent time.Time
	count     int
}

// observeClasses scans the asset's events and tallies observed source
// classes (last event time + 30-day count).
func (r *Runner) observeClasses(ctx context.Context, entityRef string) (map[string]classState, error) {
	// Assets link to events by the host value in their entity_ref
	// ("host:NAME"); only host-linked assets have event telemetry.
	parts := strings.SplitN(entityRef, ":", 2)
	if len(parts) != 2 || parts[0] != "host" {
		return map[string]classState{}, nil
	}
	hostValue := parts[1]

	since := time.Now().UTC().Add(-window)
	rows, err := r.db.QueryContext(ctx, `
		SELECT source_type, attributes, received_at FROM events
		WHERE host = ? AND received_at >= ?
		ORDER BY received_at DESC LIMIT ?`, hostValue, since, maxEventsPerAsset)
	if err != nil {
		return nil, fmt.Errorf("scan asset events: %w", err)
	}
	defer rows.Close()

	out := map[string]classState{}
	for rows.Next() {
		var (
			sourceType sql.NullString
			attrsJSON  sql.NullString
			receivedAt sql.NullTime
		)
		if err := rows.Scan(&sourceType, &attrsJSON, &receivedAt); err != nil {
			return nil, err
		}
		if !receivedAt.Valid {
			continue
		}
		ev := &event.Event{SourceType: sourceType.String, ReceivedAt: receivedAt.Time}
		if attrsJSON.Valid && attrsJSON.String != "" {
			_ = json.Unmarshal([]byte(attrsJSON.String), &ev.Attributes)
		}
		class := EventClassFor(ev)
		if class == normalization.ClassGeneric {
			continue
		}
		st := out[class]
		if st.lastEvent.IsZero() || receivedAt.Time.After(st.lastEvent) {
			st.lastEvent = receivedAt.Time
		}
		st.count++
		out[class] = st
	}
	return out, rows.Err()
}

// ComputeAll recomputes coverage for every asset and stores the observed
// rows (availability, freshness, 30-day counts).
func (r *Runner) ComputeAll(ctx context.Context) (int, error) {
	list, _, err := r.assets.List(ctx, assets.ListFilter{})
	if err != nil {
		return 0, err
	}
	for _, a := range list {
		if err := r.persist(ctx, a); err != nil {
			r.logger.Warn("coverage compute", "asset", a.ID, "error", err)
			continue
		}
	}
	return len(list), nil
}

func (r *Runner) persist(ctx context.Context, a *assets.Asset) error {
	observed, err := r.observeClasses(ctx, a.EntityRef)
	if err != nil {
		return err
	}
	for c, st := range observed {
		ls := st.lastEvent
		if err := r.store.Upsert(ctx, Row{
			AssetID:       a.ID,
			SourceClass:   c,
			Available:     true,
			LastEvent:     &ls,
			EventCount30d: st.count,
		}); err != nil {
			return err
		}
	}
	return nil
}

// MarkExpected records an analyst declaration that a source class is expected
// for an asset.
func (r *Runner) MarkExpected(ctx context.Context, assetID, class string) error {
	return r.store.MarkExpected(ctx, assetID, class)
}

// Rows returns the stored telemetry rows for an asset.
func (r *Runner) Rows(ctx context.Context, assetID string) ([]Row, error) {
	return r.store.Rows(ctx, assetID)
}

// AssetStore exposes the underlying asset store for summary computation.
func (r *Runner) AssetStore() *assets.Store { return r.assets }

// Start launches the periodic recompute loop.
func (r *Runner) Start(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n, err := r.ComputeAll(ctx); err != nil {
					r.logger.Warn("coverage recompute", "error", err, "assets", n)
				}
			}
		}
	}()
}

func round2(f float64) float64 {
	return float64(int64(f*100+0.5)) / 100
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
