package events_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"quetzalog/internal/events"
)

// EVT-SEC-01: Search LIMIT is clamped by the store even when callers forget
// their own clamp (defense in depth against unbounded result sets).
func TestEVTSec_SearchLimitClamped(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	for i := 0; i < 25; i++ {
		if err := store.Create(ctx, mkEvent("clamp-src", "info", "row")); err != nil {
			t.Fatal(err)
		}
	}

	evs, err := store.Search(ctx, events.Query{Source: "clamp-src", Limit: 999999999, Offset: -10})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(evs) != 25 {
		t.Fatalf("expected 25 rows, got %d", len(evs))
	}

	evs, err = store.Search(ctx, events.Query{Limit: -5})
	if err != nil {
		t.Fatalf("search negative limit: %v", err)
	}
	if len(evs) > events.MaxSearchLimit {
		t.Fatalf("limit clamp not enforced: %d > %d", len(evs), events.MaxSearchLimit)
	}
}

// EVT-SEC-02: attribute-key injection attempts are rejected with
// ErrInvalidQuery (never interpolated raw into SQL).
func TestEVTSec_AttrKeyInjectionRejected(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	evilKeys := []string{
		`a"="$1" OR 1=1 --`,
		`key'); DROP TABLE events; --`,
		`$.path`,
		`k e y`,
		`key"`+"'}",
		`key\\`,
	}
	for _, k := range evilKeys {
		_, err := store.Search(ctx, events.Query{Attributes: map[string]string{k: "1"}})
		if err == nil {
			t.Errorf("evil attr key %q accepted (SEC-02)", k)
			continue
		}
		if !errors.Is(err, events.ErrInvalidQuery) {
			t.Errorf("evil attr key %q gave non-validation error: %v", k, err)
		}
		if strings.Contains(strings.ToUpper(err.Error()), "SYNTAX") {
			t.Errorf("possible SQL injection reached engine for key %q: %v", k, err)
		}
	}

	// legit keys still work
	if err := store.Create(ctx, mkEvent("attr-src", "info", "hi")); err != nil {
		t.Fatal(err)
	}
	ev := mkEvent("attr-src2", "info", "hi")
	ev.Attributes = map[string]any{"env": "prod"}
	if err := store.Create(ctx, ev); err != nil {
		t.Fatal(err)
	}
	evs, err := store.Search(ctx, events.Query{Attributes: map[string]string{"env": "prod"}})
	if err != nil {
		t.Fatalf("legit attr filter: %v", err)
	}
	if len(evs) != 1 {
		t.Errorf("legit attr filter returned %d rows, want 1", len(evs))
	}
}

// EVT-SEC-03: FTS5 text search fuzz — adversarial match syntax must be
// treated as data (sanitized), never causing SQL errors or crashes.
func TestEVTSec_FTSInjectionFuzz(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	if err := store.Create(ctx, mkEvent("fts-src", "info", "match me please")); err != nil {
		t.Fatal(err)
	}

	payloads := []string{
		`" OR 1=1 --`,
		`"); DROP TABLE events; --`,
		`NEAR(evil, "x")`,
		`{match} AND NOT {x}`,
		`"unbalanced`,
		`""""""""`,
		`*`,
		`""`,
		`‮unicode-rlo`,
		`x\x00y`,
		strings.Repeat("word ", 500),
	}
	for _, p := range payloads {
		if _, err := store.Search(ctx, events.Query{Text: p, Limit: 5}); err != nil {
			t.Errorf("fts payload %q errored: %v (SEC-03)", p, err)
		}
		if _, err := store.Count(ctx, events.Query{Text: p}); err != nil {
			t.Errorf("fts count payload %q errored: %v (SEC-03)", p, err)
		}
	}
	// data intact
	n, err := store.Count(ctx, events.Query{})
	if err != nil || n < 1 {
		t.Errorf("events table damaged after fuzz: count=%d err=%v", n, err)
	}
}

// EVT-SEC-04: ORDER BY column whitelist rejects arbitrary identifiers.
func TestEVTSec_SortWhitelist(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	for _, bad := range []string{"1;--", "id, (SELECT 1)", "ROWID", "json_extract(x,'$.a')"} {
		if _, err := store.Search(ctx, events.Query{SortBy: bad, Limit: 5}); err == nil {
			t.Errorf("invalid sort column %q accepted", bad)
		}
	}
	for _, good := range []string{"timestamp", "id", "severity", "TIMESTAMP"} {
		if _, err := store.Search(ctx, events.Query{SortBy: good, Limit: 5}); err != nil {
			t.Errorf("valid sort column %q rejected: %v", good, err)
		}
	}
}
