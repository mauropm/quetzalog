package coverage

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"quetzalog/internal/assets"
	"quetzalog/internal/database"
	"quetzalog/internal/normalization"
	"quetzalog/pkg/event"
)

func newTestEnv(t *testing.T) (*sql.DB, *assets.Store, *Store, *Runner) {
	t.Helper()
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	assetStore := assets.NewStore(db)
	store := NewStore(db)
	runner := NewRunner(db, assetStore, store, nil, 24*time.Hour)
	return db, assetStore, store, runner
}

func TestWeightsFor(t *testing.T) {
	if w := WeightsFor("server", "windows server 2022"); len(w) == 0 {
		t.Error("windows server should have weights")
	}
	if w := WeightsFor("host", "linux"); len(w) == 0 {
		t.Error("linux host should have weights")
	}
	if w := WeightsFor("network", "cisco ios"); len(w) == 0 {
		t.Error("network device should have weights")
	}
	if w := WeightsFor("cloud-workload", ""); len(w) != 0 {
		t.Errorf("unknown platform must have no weights, got %d", len(w))
	}
}

func TestEventClassFor(t *testing.T) {
	if got := EventClassFor(nil); got != normalization.ClassGeneric {
		t.Errorf("nil event: %q", got)
	}
	// Explicit, valid source_class is trusted.
	if got := EventClassFor(attrsEvent(normalization.ClassLinuxAuditd)); got != normalization.ClassLinuxAuditd {
		t.Errorf("auditd: %q", got)
	}
	// Unknown class falls back to generic (never a fake specific class).
	if got := EventClassFor(attrsEvent("os.mars.auditd")); got != normalization.ClassGeneric {
		t.Errorf("unknown class: %q", got)
	}
	// No attribute → generic.
	if got := EventClassFor(&event.Event{}); got != normalization.ClassGeneric {
		t.Errorf("no attribute: %q", got)
	}
}

func TestCoverageForLinuxHost(t *testing.T) {
	db, assetStore, _, runner := newTestEnv(t)
	ctx := context.Background()

	a, err := assetStore.Create(ctx, &assets.Asset{
		EntityType: "server",
		EntityRef:  "host:db1",
		Name:       "db1",
		OS:         "linux",
	})
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	insertTestEvents(t, db, "db1", []string{
		`{"source_class":"` + normalization.ClassLinuxAuditd + `"}`,
		`{"source_class":"` + normalization.ClassLinuxSSHD + `"}`,
		`{}`,
	})

	cov, err := runner.CoverageFor(ctx, a.ID)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	// auditd(0.30) + sshd(0.15) = 45% of the linux weight set.
	if cov.CoveragePct != 45 {
		t.Errorf("coverage pct: %v", cov.CoveragePct)
	}
	contains(t, cov.Available, normalization.ClassLinuxAuditd)
	contains(t, cov.Available, normalization.ClassLinuxSSHD)
	contains(t, cov.Missing, normalization.ClassLinuxJournal)
	contains(t, cov.Missing, normalization.ClassNetFlow)
	if contains(t, cov.Available, normalization.ClassGeneric) {
		t.Error("generic must never satisfy a weight")
	}
}

func TestCoverageForStale(t *testing.T) {
	db, assetStore, _, runner := newTestEnv(t)
	ctx := context.Background()

	a, err := assetStore.Create(ctx, &assets.Asset{
		EntityType: "server",
		EntityRef:  "host:old",
		Name:       "old",
		OS:         "linux",
	})
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	// One stale auditd event (48h old) — inside the 30-day window, older
	// than the 24h freshness threshold.
	old := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339)
	if _, err := db.ExecContext(ctx,
		`INSERT INTO events (id, timestamp, received_at, source, source_type, host, severity, message, attributes)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		"evt-stale", old, old, "test", "json", "old", "info", "stale",
		`{"source_class":"`+normalization.ClassLinuxAuditd+`"}`); err != nil {
		t.Fatalf("insert: %v", err)
	}

	cov, err := runner.CoverageFor(ctx, a.ID)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	contains(t, cov.Available, normalization.ClassLinuxAuditd)
	if !contains(t, cov.Stale, normalization.ClassLinuxAuditd) {
		t.Errorf("auditd should be stale: %+v", cov)
	}
}

func TestStoreRoundTrip(t *testing.T) {
	_, assetStore, store, _ := newTestEnv(t)
	ctx := context.Background()

	a, err := assetStore.Create(ctx, &assets.Asset{
		EntityType: "server",
		EntityRef:  "host:rt",
		Name:       "rt",
		OS:         "linux",
	})
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	row := Row{
		AssetID:       a.ID,
		SourceClass:   normalization.ClassLinuxAuditd,
		Available:     true,
		LastEvent:     &now,
		EventCount30d: 42,
		Collector:     "auditd-agent",
	}
	if err := store.Upsert(ctx, row); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := store.MarkExpected(ctx, a.ID, normalization.ClassLinuxAuditd); err != nil {
		t.Fatalf("mark expected: %v", err)
	}
	older := now.Add(-time.Hour)
	// A later pass must not regress the observed last-event time, and it
	// rewrites the full-window count.
	if err := store.Upsert(ctx, Row{
		AssetID:       a.ID,
		SourceClass:   normalization.ClassLinuxAuditd,
		Available:     true,
		LastEvent:     &older,
		EventCount30d: 42,
	}); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}

	rows, err := store.Rows(ctx, a.ID)
	if err != nil {
		t.Fatalf("rows: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows: %d", len(rows))
	}
	got := rows[0]
	if !got.Available || !got.Expected || got.EventCount30d != 42 || got.Collector != "auditd-agent" {
		t.Errorf("row mismatch: %+v", got)
	}
	if got.LastEvent == nil || !got.LastEvent.Equal(now) {
		t.Errorf("last_event must keep the newer timestamp, got %v", got.LastEvent)
	}
}

func TestComputeAllPersists(t *testing.T) {
	db, assetStore, store, runner := newTestEnv(t)
	ctx := context.Background()

	a, err := assetStore.Create(ctx, &assets.Asset{
		EntityType: "host",
		EntityRef:  "host:web1",
		Name:       "web1",
		OS:         "windows server 2019",
	})
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	insertTestEvents(t, db, "web1", []string{
		`{"source_class":"` + normalization.ClassWinSysmon + `"}`,
		`{"source_class":"` + normalization.ClassWinSysmon + `"}`,
		`{"source_class":"` + normalization.ClassWinSecurity + `"}`,
	})

	if n, err := runner.ComputeAll(ctx); err != nil {
		t.Fatalf("compute all: %v", err)
	} else if n != 1 {
		t.Errorf("computed assets: %d", n)
	}

	rows, err := store.Rows(ctx, a.ID)
	if err != nil {
		t.Fatalf("rows: %v", err)
	}
	byClass := map[string]Row{}
	for _, r := range rows {
		byClass[r.SourceClass] = r
	}
	sysmon, ok := byClass[normalization.ClassWinSysmon]
	if !ok || !sysmon.Available || sysmon.EventCount30d != 2 {
		t.Errorf("sysmon row: %+v", sysmon)
	}
	sec, ok := byClass[normalization.ClassWinSecurity]
	if !ok || !sec.Available {
		t.Errorf("security row: %+v", sec)
	}
}

func TestCoverageNoWeightsNoClaim(t *testing.T) {
	_, assetStore, _, runner := newTestEnv(t)
	ctx := context.Background()

	a, err := assetStore.Create(ctx, &assets.Asset{
		EntityType: "cloud_resource",
		EntityRef:  "cloud:pod-x",
		Name:       "pod-x",
	})
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	cov, err := runner.CoverageFor(ctx, a.ID)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if cov.CoveragePct != 0 || len(cov.Available) != 0 || len(cov.Missing) != 0 {
		t.Errorf("unknown platform must yield no coverage claim: %+v", cov)
	}
}

func insertTestEvents(t *testing.T, db *sql.DB, host string, attrs []string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	for i, a := range attrs {
		_, err := db.ExecContext(context.Background(),
			`INSERT INTO events (id, timestamp, received_at, source, source_type, host, severity, message, attributes)
			 VALUES (?,?,?,?,?,?,?,?,?)`,
			"evt-cov-"+string(rune('a'+i))+host, now, now, "test", "json", host, "info", "test event", a)
		if err != nil {
			t.Fatalf("insert event: %v", err)
		}
	}
}

func attrsEvent(class string) *event.Event {
	return &event.Event{Attributes: map[string]any{"source_class": class}}
}

func contains(t *testing.T, list []string, want string) bool {
	t.Helper()
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
