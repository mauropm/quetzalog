package api_test

import (
	"fmt"
	"sync"
	"testing"
)

func TestAPI_ConcurrentEventWritesAndReads(t *testing.T) {
	e := newEnv(t)

	const writes = 100
	var wg sync.WaitGroup
	errs := make(chan error, writes*2)

	for i := 0; i < writes; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := map[string]any{
				"id":        fmt.Sprintf("stress-%d", i),
				"message": fmt.Sprintf("stress event %d", i),
				"source":  "stress",
				"attributes": map[string]any{
					"tenant": "acme",
					"index":  i,
				},
			}
			w, _ := do(e, "POST", "/api/v1/events", body, nil)
			if w.Code != 201 {
				errs <- fmt.Errorf("create %d returned %d %s", i, w.Code, w.Body.String())
			}
		}(i)
	}

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w, _ := do(e, "GET", "/api/v1/events?attr.tenant=acme", nil, nil)
			if w.Code != 200 {
				errs <- fmt.Errorf("list returned %d %s", w.Code, w.Body.String())
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	w, _ := do(e, "GET", "/api/v1/events?attr.tenant=acme", nil, nil)
	if w.Code != 200 {
		t.Fatalf("final list %d", w.Code)
	}
	out := decodeBody(t, w)
	data, _ := out["data"].(map[string]any)
	events, ok := data["events"].([]any)
	if !ok {
		t.Fatalf("missing event list: %#v", out)
	}
	if len(events) != writes {
		t.Fatalf("want %d events, got %d", writes, len(events))
	}
}

func TestAPI_ConcurrentBatchIngest(t *testing.T) {
	e := newEnv(t)
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for batch := 0; batch < 10; batch++ {
		wg.Add(1)
		go func(batch int) {
			defer wg.Done()
			body := map[string]any{
				"events": makeEvents(batch, 20),
			}
			w, _ := do(e, "POST", "/api/v1/events/batch", body, nil)
			if w.Code != 201 {
				errs <- fmt.Errorf("batch %d returned %d %s", batch, w.Code, w.Body.String())
				return
			}
			out := decodeBody(t, w)
			data, _ := out["data"].(map[string]any)
			created, ok := data["created"].(float64)
			if !ok || int(created) != 20 {
				errs <- fmt.Errorf("batch %d created %v", batch, out["data"])
			}
		}(batch)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	w, _ := do(e, "GET", "/api/v1/events?limit=500", nil, nil)
	out := decodeBody(t, w)
	data, _ := out["data"].(map[string]any)
	events := data["events"].([]any)
	if len(events) != 200 {
		t.Fatalf("want 200 batch events, got %d", len(events))
	}
}

func makeEvents(batch, n int) []map[string]any {
	events := make([]map[string]any, n)
	for i := 0; i < n; i++ {
		events[i] = map[string]any{
			"id":      fmt.Sprintf("batch-%d-%d", batch, i),
			"message": fmt.Sprintf("batch event %d/%d", batch, i),
			"source":  "batch",
		}
	}
	return events
}