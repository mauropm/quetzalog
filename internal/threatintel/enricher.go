package threatintel

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"

	"quetzalog/internal/risk"
	"quetzalog/pkg/event"
)

// Enricher runs indicator matching against the event stream on a bounded
// async queue (architecture doc, principle 17: the ingestion write path
// stays TI-free; enrichment is background and skippable). Matches are
// recorded back on the event as attributes (threat.indicators /
// threat.severity), the indicator hit counters are bumped, co-occurrence
// correlations are recorded, and a risk contribution is added for the
// matched entity.
type Enricher struct {
	store  *Store
	risk   *risk.EntityRiskStore
	db     *sql.DB
	logger *slog.Logger

	queue  chan *event.Event
	once   sync.Once
	wg     sync.WaitGroup
}

// NewEnricher creates the enricher. risk may be nil to skip risk
// contributions.
func NewEnricher(store *Store, riskStore *risk.EntityRiskStore, db *sql.DB, logger *slog.Logger) *Enricher {
	if logger == nil {
		logger = slog.Default()
	}
	return &Enricher{store: store, risk: riskStore, db: db, logger: logger, queue: make(chan *event.Event, 1024)}
}

// Enqueue accepts an event for indicator matching. It never blocks: when
// the queue is full the event is dropped (a metric-worthy loss, never an
// ingestion stall).
func (e *Enricher) Enqueue(ev *event.Event) {
	if ev == nil {
		return
	}
	select {
	case e.queue <- ev:
	default:
		e.logger.Warn("ti enrichment queue full, dropping event", "id", ev.ID)
	}
}

// Start launches the workers; it returns immediately.
func (e *Enricher) Start(workers int) {
	if workers <= 0 {
		workers = 2
	}
	for i := 0; i < workers; i++ {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			for ev := range e.queue {
				if err := e.process(context.Background(), ev); err != nil {
					e.logger.Warn("ti enrichment", "event", ev.ID, "error", err)
				}
			}
		}()
	}
}

// Stop closes the queue and waits for the workers to drain.
func (e *Enricher) Stop() {
	e.once.Do(func() { close(e.queue) })
	e.wg.Wait()
}

// candidateValues are the event fields (plus attributes) checked against
// the indicator store, as "type\x00value" keys (deduplicated).
func candidateValues(ev *event.Event) map[string]bool {
	out := map[string]bool{}
	add := func(typ, v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		out[typ+"\x00"+v] = true
	}
	add("ip", ev.SourceIP)
	add("ip", ev.DestinationIP)
	add("ip", ev.IP)
	add("host", ev.Host)
	add("user", ev.User)
	if ev.Attributes != nil {
		for _, k := range []string{"domain", "url", "email", "file_hash", "hash"} {
			if s, ok := ev.Attributes[k].(string); ok {
				typ := mapAttrType(k)
				add(typ, s)
			}
		}
	}
	return out
}

func mapAttrType(k string) string {
	switch k {
	case "domain":
		return "domain"
	case "url":
		return "url"
	case "email":
		return "email"
	case "file_hash", "hash":
		return "hash"
	}
	return "domain"
}

var severityRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

func (e *Enricher) process(ctx context.Context, ev *event.Event) error {
	var hits []Indicator
	seen := map[string]bool{}
	for key := range candidateValues(ev) {
		parts := strings.SplitN(key, "\x00", 2)
		if len(parts) != 2 {
			continue
		}
		list, err := e.store.LookupByType(ctx, parts[0], parts[1])
		if err != nil {
			return err
		}
		for _, h := range list {
			if seen[h.ID] {
				continue
			}
			seen[h.ID] = true
			hits = append(hits, h)
		}
	}
	if len(hits) == 0 {
		return nil
	}

	ids := make([]string, 0, len(hits))
	top := ""
	for _, h := range hits {
		ids = append(ids, h.ID)
		if severityRank[h.Severity] > severityRank[top] {
			top = h.Severity
		}
	}

	if err := e.markEvent(ctx, ev.ID, ids, top); err != nil {
		return err
	}
	if err := e.store.RecordHits(ctx, ids, ev.ID); err != nil {
		return err
	}
	e.recordRisk(ctx, ev, hits)
	return nil
}

// markEvent attaches the match result to the event's attributes
// (threat.indicators + threat.severity). Attribute updates are additive;
// the raw payload and other attributes are untouched.
func (e *Enricher) markEvent(ctx context.Context, eventID string, ids []string, severity string) error {
	b, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	_, err = e.db.ExecContext(ctx,
		`UPDATE events SET attributes = json_set(
			COALESCE(attributes, '{}'),
			'$."threat"."indicators"', json(?),
			'$."threat"."severity"', ?
		) WHERE id = ?`, string(b), severity, eventID)
	if err != nil {
		return fmt.Errorf("mark event %s: %w", eventID, err)
	}
	return nil
}

func (e *Enricher) recordRisk(ctx context.Context, ev *event.Event, hits []Indicator) {
	if e.risk == nil {
		return
	}
	type key struct{ typ, value string }
	maxPer := map[key]Indicator{}
	for _, h := range hits {
		for _, c := range []key{{"ip", ev.SourceIP}, {"ip", ev.IP}, {"host", ev.Host}, {"user", ev.User}} {
			if c.value == "" {
				continue
			}
			if cur, ok := maxPer[c]; !ok || severityRank[h.Severity] > severityRank[cur.Severity] {
				maxPer[c] = h
			}
		}
	}
	for k, h := range maxPer {
		points := severityPoints(h.Severity) * h.Confidence
		_ = e.risk.Record(ctx, risk.Contribution{
			EntityType:  k.typ,
			EntityValue: k.value,
			SourceType:  "event",
			SourceID:    "ti-enricher",
			Description: "TI indicator match " + h.Type + ":" + h.Value + " (" + h.Severity + ", confidence " + formatConf(h.Confidence) + ", source " + h.Source + ")",
			Points:      points,
			EventID:     ev.ID,
		})
	}
}

func severityPoints(s string) float64 {
	switch s {
	case "critical":
		return 25
	case "high":
		return 15
	case "medium":
		return 8
	case "low":
		return 4
	}
	return 0
}

func formatConf(c float64) string {
	return strconv.FormatFloat(c, 'f', 2, 64)
}
