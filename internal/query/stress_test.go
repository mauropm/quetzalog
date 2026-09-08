package query_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"quetzalog/internal/events"
	"quetzalog/internal/query"
	"quetzalog/pkg/event"
)

func TestExecute_ConcurrentSearches(t *testing.T) {
	svc, db := setup(t)
	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	seed(t, db, 200, base)

	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.Execute(context.Background(), query.SearchRequest{
				Query: "source=src0 OR source=src1",
				Limit: 50,
			})
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestExecute_ComplexPipeStress(t *testing.T) {
	svc, db := setup(t)
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	seed(t, db, 500, base)

	resp, err := svc.Execute(context.Background(), query.SearchRequest{
		Query: "source=src0 OR source=src1 | sort -timestamp | head 25",
		Limit: 50,
	})
	if err != nil {
		t.Fatalf("complex search: %v", err)
	}
	if resp.Count < 25 {
		t.Fatalf("want at least 25 matches, got %d", resp.Count)
	}
	if len(resp.Results) != 25 {
		t.Fatalf("head command returned %d events", len(resp.Results))
	}
	if len(resp.Results) >= 2 {
		first, ok1 := resp.Results[0]["timestamp"].(time.Time)
		second, ok2 := resp.Results[1]["timestamp"].(time.Time)
		if !ok1 || !ok2 || !first.After(second) {
			t.Errorf("descending timestamp sort did not order results: %#v %#v", resp.Results[0]["timestamp"], resp.Results[1]["timestamp"])
		}
	}
}

func TestExecute_LargeOffsetDoesNotPanic(t *testing.T) {
	svc, db := setup(t)
	seed(t, db, 20, time.Now())

	for _, offset := range []int{-1, 0, 10, 1000} {
		_, err := svc.Execute(context.Background(), query.SearchRequest{
			Query:  "source=src0",
			Limit:  10,
			Offset: offset,
		})
		if err != nil {
			t.Errorf("offset %d returned error: %v", offset, err)
		}
	}
}

func TestExecute_AttributeStress(t *testing.T) {
	svc, db := setup(t)
	store := events.NewStore(db)
	ctx := context.Background()
	for i := 0; i < 250; i++ {
		ev := event.NewEvent()
		ev.Source = fmt.Sprintf("stress%d", i%4)
		ev.Message = fmt.Sprintf("attr stress %d", i)
		ev.Timestamp = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Minute)
		ev.Attributes["tenant"] = fmt.Sprintf("tenant-%d", i%10)
		if err := store.Create(ctx, ev); err != nil {
			t.Fatalf("create: %v", err)
		}
	}

	resp, err := svc.Execute(ctx, query.SearchRequest{
		Query: "tenant=tenant-3",
		Limit: 100,
	})
	if err != nil {
		t.Fatalf("attribute search: %v", err)
	}
	if resp.Count != 25 {
		t.Fatalf("want 25 attribute matches, got %d", resp.Count)
	}
}