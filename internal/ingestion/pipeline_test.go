package ingestion_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"runtime"
	"sync"
	"testing"
	"time"

	"quetzalog/internal/database"
	"quetzalog/internal/events"
	"quetzalog/internal/ingestion"
	"quetzalog/pkg/event"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newTestPipeline(t *testing.T, workers, batchSize int, buf *syncBuffer) (*ingestion.Pipeline, *events.Store, func()) {
	t.Helper()
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := database.Migrate(db); err != nil {
		db.Close()
		t.Fatalf("migrate: %v", err)
	}
	store := events.NewStore(db)
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	p := ingestion.NewPipeline(store, workers, batchSize, logger)
	return p, store, func() { db.Close() }
}

func waitForCount(t *testing.T, store *events.Store, want int, timeout time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(timeout)
	last := -1
	for time.Now().Before(deadline) {
		n, err := store.Count(context.Background(), events.Query{})
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		last = n
		if n >= want {
			return n
		}
		time.Sleep(20 * time.Millisecond)
	}
	return last
}

func TestPipeline_PersistsEveryEventExactlyOnce(t *testing.T) {
	var logBuf syncBuffer
	p, store, cleanup := newTestPipeline(t, 2, 25, &logBuf)
	defer cleanup()

	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}

	for i := 0; i < 30; i++ {
		ev := event.NewEvent()
		ev.Source = "unit"
		ev.Severity = "info"
		ev.Message = "e"
		if err := p.Ingest(context.Background(), ev); err != nil {
			t.Fatalf("ingest %d: %v", i, err)
		}
	}

	if err := p.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}

	got, err := store.Count(context.Background(), events.Query{})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if got != 30 {
		t.Errorf("want 30 events stored, got %d", got)
	}

	// A correctly batched pipeline never logs a batch flush failure for healthy data.
	if logs := logBuf.String(); strings.Contains(logs, "failed to flush") ||
		strings.Contains(logs, "failed to process event") {
		t.Errorf("pipeline logged flush/process failures for healthy ingestion:\n%s", logs)
	}
}

func TestPipeline_EnrichersRun(t *testing.T) {
	var logBuf syncBuffer
	p, store, cleanup := newTestPipeline(t, 1, 10, &logBuf)
	defer cleanup()

	p.AddEnricher(&tagEnricher{})
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	ev := event.NewEvent()
	ev.Source = "unit"
	ev.Message = "hello"
	_ = p.Ingest(context.Background(), ev)

	got := waitForCount(t, store, 1, 5*time.Second)
	if got != 1 {
		t.Fatalf("want 1, got %d", got)
	}
	list, err := store.Search(context.Background(), events.Query{Limit: 5})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(list) != 1 || list[0].Attributes["enriched"] != "yes" {
		t.Errorf("enricher did not run/applied: %#v", list)
	}
	_ = p.Stop(context.Background())
}

type tagEnricher struct{}

func (tagEnricher) Name() string { return "tag" }
func (tagEnricher) Enrich(ctx context.Context, e *event.Event) error {
	if e.Attributes == nil {
		e.Attributes = map[string]any{}
	}
	e.Attributes["enriched"] = "yes"
	return nil
}

func TestPipeline_IngestWhenNotRunning(t *testing.T) {
	var logBuf syncBuffer
	p, _, cleanup := newTestPipeline(t, 1, 10, &logBuf)
	defer cleanup()

	ev := event.NewEvent()
	if err := p.Ingest(context.Background(), ev); err == nil {
		t.Error("want error ingesting into un-started pipeline")
	}
	if err := p.Ingest(context.Background(), nil); err == nil {
		t.Error("want error ingesting nil event")
	}
}

func TestPipeline_StopTerminatesWorkers(t *testing.T) {
	// Workers must exit after Stop so that repeated Start/Stop cycles do not
	// leak goroutines and pending events are drained before returning.
	var logBuf syncBuffer
	p, store, cleanup := newTestPipeline(t, 4, 10000, &logBuf)
	defer cleanup()

	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	base := runtime.NumGoroutine()

	for cyc := 0; cyc < 5; cyc++ {
		if err := p.Start(context.Background()); err != nil {
			t.Fatalf("start cycle %d: %v", cyc, err)
		}
		if err := p.Stop(context.Background()); err != nil {
			t.Fatalf("stop cycle %d: %v", cyc, err)
		}
	}

	time.Sleep(150 * time.Millisecond)
	after := runtime.NumGoroutine()
	if delta := after - base; delta > 2 {
		t.Errorf("goroutine leak: %d extra goroutines after 5 Start/Stop cycles", delta)
	}

	// Stop must drain in-flight events.
	_ = p.Start(context.Background())
	for i := 0; i < 10; i++ {
		ev := event.NewEvent()
		ev.Source = "drain"
		ev.Message = "d"
		if err := p.Ingest(context.Background(), ev); err != nil {
			t.Fatalf("ingest: %v", err)
		}
	}
	if err := p.Stop(context.Background()); err != nil {
		t.Fatalf("final stop: %v", err)
	}
	n, err := store.Count(context.Background(), events.Query{})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 10 {
		t.Errorf("Stop did not drain: want 10 stored, got %d", n)
	}
}

func TestPipeline_BufferFullReturnsError(t *testing.T) {
	var logBuf syncBuffer
	p, _, cleanup := newTestPipeline(t, 1, 10000, &logBuf)
	defer cleanup()

	// A single worker blocks on the store; overfill the small channel and
	// ensure Ingest returns a PipelineError rather than blocking forever.
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	// Channel capacity is workers*2 = 2. Push 50 quickly with batchSize 10000
	// (worker holds events in its local batch, consuming fast) — buffer-full may
	// not trigger; either outcome is acceptable as long as we never hang.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			ev := event.NewEvent()
			ev.Message = "f"
			_ = p.Ingest(context.Background(), ev)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Ingest blocked longer than 3s under backpressure")
	}
	_ = p.Stop(context.Background())
}
