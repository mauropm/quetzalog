package events_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"quetzalog/internal/events"
)

func TestStore_ConcurrentWritersAndReaders(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()

	const writers = 8
	const perWriter = 100
	ctx := context.Background()

	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, writers*2)

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < perWriter; i++ {
				ev := mkEvent("stress", "info", fmt.Sprintf("writer=%d i=%d", w, i))
				ev.Attributes["writer"] = w
				if err := store.Create(ctx, ev); err != nil {
					errs <- fmt.Errorf("create: %w", err)
					return
				}
			}
		}(w)
	}

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 10; j++ {
				if _, err := store.Search(ctx, events.Query{Limit: 20}); err != nil {
					errs <- fmt.Errorf("search: %w", err)
					return
				}
				if _, err := store.Count(ctx, events.Query{Source: "stress"}); err != nil {
					errs <- fmt.Errorf("count: %w", err)
					return
				}
			}
		}()
	}

	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	got, err := store.Search(ctx, events.Query{Source: "stress", Limit: writers*perWriter + 10})
	if err != nil {
		t.Fatalf("search after stress: %v", err)
	}
	if len(got) != writers*perWriter {
		t.Fatalf("want %d stress events, got %d", writers*perWriter, len(got))
	}
}

func TestStore_AttributeStressUsesIndexedJSON(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	for i := 0; i < 500; i++ {
		ev := mkEvent("stress", "info", fmt.Sprintf("tenant event %d", i))
		ev.Attributes["tenant"] = fmt.Sprintf("tenant-%d", i%25)
		if err := store.Create(ctx, ev); err != nil {
			t.Fatalf("create: %v", err)
		}
	}

	got, err := store.Search(ctx, events.Query{
		Attributes: map[string]string{"tenant": "tenant-7"},
		Limit:      1000,
	})
	if err != nil {
		t.Fatalf("attribute search: %v", err)
	}
	if len(got) != 20 {
		t.Fatalf("want 20 attribute matches, got %d", len(got))
	}
}

func TestStore_HighVolumeFTS(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	const total = 1000
	for i := 0; i < total; i++ {
		msg := "accepted publickey"
		if i%10 == 0 {
			msg = "failed password admin"
		}
		ev := mkEvent("sshd", "warning", fmt.Sprintf("%s %d", msg, i))
		if err := store.Create(ctx, ev); err != nil {
			t.Fatalf("create: %v", err)
		}
	}

	got, err := store.Search(ctx, events.Query{Text: "failed"})
	if err != nil {
		t.Fatalf("FTS search: %v", err)
	}
	if len(got) != total/10 {
		t.Fatalf("want %d failed events, got %d", total/10, len(got))
	}
}

func TestStore_TimeWindowIsStable(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	old := mkEvent("window", "info", "old event")
	old.Timestamp = time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Millisecond)
	if err := store.Create(ctx, old); err != nil {
		t.Fatal(err)
	}
	fresh := mkEvent("window", "info", "new event")
	fresh.Timestamp = time.Now().UTC().Truncate(time.Millisecond)
	if err := store.Create(ctx, fresh); err != nil {
		t.Fatal(err)
	}

	got, err := store.Search(ctx, events.Query{Start: time.Now().Add(-30 * time.Minute)})
	if err != nil {
		t.Fatalf("time window search: %v", err)
	}
	if len(got) != 1 || got[0].ID != fresh.ID {
		t.Fatalf("time window included the wrong events: %d", len(got))
	}
}