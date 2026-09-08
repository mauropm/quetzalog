package ingestion_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"quetzalog/internal/events"
	"quetzalog/internal/ingestion"
	"quetzalog/pkg/event"
)

func ingestWithBackpressure(t *testing.T, p *ingestion.Pipeline, ev *event.Event) {
	t.Helper()
	for i := 0; i < 10000; i++ {
		err := p.Ingest(context.Background(), ev)
		if err == nil {
			return
		}
		if !strings.Contains(err.Error(), "buffer full") {
			t.Fatalf("unexpected ingest error: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("pipeline remained full while ingesting stress events")
}

func TestPipeline_HighVolumeConcurrentIngest(t *testing.T) {
	var logBuf syncBuffer
	p, store, cleanup := newTestPipeline(t, 4, 100, &logBuf)
	defer cleanup()
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer p.Stop(context.Background())

	const producers = 8
	const perProducer = 250
	total := producers * perProducer

	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < producers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start
			for n := 0; n < perProducer; n++ {
				ev := event.NewEvent()
				ev.Source = "stress"
				ev.Message = fmt.Sprintf("producer=%d seq=%d", id, n)
				ev.Attributes["producer"] = id
				ingestWithBackpressure(t, p, ev)
			}
		}(i)
	}

	close(start)
	wg.Wait()

	got := waitForCount(t, store, total, 30*time.Second)
	if got != total {
		t.Fatalf("expected %d persisted events, got %d", total, got)
	}

	list, err := store.Search(context.Background(), events.Query{Source: "stress", Limit: total + 10})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	seen := make(map[string]bool, total)
	for _, ev := range list {
		if seen[ev.ID] {
			t.Fatalf("duplicate event persisted: %s", ev.ID)
		}
		seen[ev.ID] = true
	}
}

func TestPipeline_BurstThenGracefulDrain(t *testing.T) {
	var logBuf syncBuffer
	p, store, cleanup := newTestPipeline(t, 2, 25, &logBuf)
	defer cleanup()
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}

	for i := 0; i < 250; i++ {
		ev := event.NewEvent()
		ev.Source = "burst"
		ev.Message = fmt.Sprintf("burst %d", i)
		ingestWithBackpressure(t, p, ev)
	}
	if err := p.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}

	got, err := store.Count(context.Background(), events.Query{Source: "burst"})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if got != 250 {
		t.Fatalf("Stop must drain all accepted events, got %d", got)
	}
}

func TestPipeline_StopUnderConcurrentLoad(t *testing.T) {
	var logBuf syncBuffer
	p, store, cleanup := newTestPipeline(t, 4, 25, &logBuf)
	defer cleanup()
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}

	var wg sync.WaitGroup
	stopped := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for n := 0; n < 500; n++ {
				select {
				case <-stopped:
					return
				default:
				}
				ev := event.NewEvent()
				ev.Source = "shutdown-load"
				ev.Message = fmt.Sprintf("thread=%d n=%d", id, n)
				// Errors after Stop are expected and are proof that the bounded
				// pipeline does not accept unbounded backlog during shutdown.
				_ = p.Ingest(context.Background(), ev)
			}
		}(i)
	}

	time.Sleep(100 * time.Millisecond)
	close(stopped)
	if err := p.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
	wg.Wait()

	if _, err := store.Count(context.Background(), events.Query{Source: "shutdown-load"}); err != nil {
		t.Fatalf("count after shutdown: %v", err)
	}
}

func TestPipeline_BackpressureRejectsWithoutDeadlock(t *testing.T) {
	var logBuf syncBuffer
	p, _, cleanup := newTestPipeline(t, 1, 50, &logBuf)
	defer cleanup()
	// Deliberately do not Start so every Ingest returns quickly.
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 1000; i++ {
			ev := event.NewEvent()
			ev.Message = "not started"
			if err := p.Ingest(context.Background(), ev); err == nil {
				done <- fmt.Errorf("ingest into stopped pipeline returned success at %d", i)
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Ingest blocked when pipeline was not started")
	}
}

var _ = (*ingestion.Pipeline)(nil)
var _ events.Query