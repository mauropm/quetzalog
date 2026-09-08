package events_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"quetzalog/internal/database"
	"quetzalog/internal/events"
	"quetzalog/pkg/event"
)

func setupStore(t *testing.T) (*events.Store, func()) {
	t.Helper()
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := database.Migrate(db); err != nil {
		db.Close()
		t.Fatalf("migrate: %v", err)
	}
	return events.NewStore(db), func() { db.Close() }
}

func mkEvent(source, severity, message string) *event.Event {
	ev := event.NewEvent()
	ev.Source = source
	ev.Severity = severity
	ev.Message = message
	ev.Timestamp = time.Now().UTC().Truncate(time.Millisecond)
	return ev
}

func TestCreateGet_RoundTripWithAttributes(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	ev := mkEvent("auth", "err", "failed password for bob")
	ev.Host = "web01"
	ev.User = "bob"
	ev.SourceIP = "10.0.0.5"
	ev.Attributes["user"] = "bob"
	ev.Attributes["attempt"] = 3

	if err := store.Create(ctx, ev); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := store.GetByID(ctx, ev.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Message != ev.Message {
		t.Errorf("message: got %q want %q", got.Message, ev.Message)
	}
	if got.Host != "web01" || got.User != "bob" || got.SourceIP != "10.0.0.5" {
		t.Errorf("fields mismatch: %+v", got)
	}
	// Attributes must round-trip through storage.
	if got.Attributes["user"] != "bob" {
		t.Errorf("attributes lost: got %#v", got.Attributes)
	}
}

func TestSearch_AttributeFilter(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	ev := mkEvent("app", "info", "cache miss")
	ev.Attributes["tenant"] = "acme"
	if err := store.Create(ctx, ev); err != nil {
		t.Fatalf("create: %v", err)
	}
	other := mkEvent("app", "info", "cache hit")
	other.Attributes["tenant"] = "globex"
	if err := store.Create(ctx, other); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := store.Search(ctx, events.Query{Attributes: map[string]string{"tenant": "acme"}})
	if err != nil {
		t.Fatalf("Search with attribute filter returned error (should be supported): %v", err)
	}
	if len(got) != 1 || got[0].ID != ev.ID {
		t.Errorf("attribute filter wrong: %d results", len(got))
	}
}

func TestSearch_FTSMessage(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		ev := mkEvent("sshd", "warning", fmt.Sprintf("Failed password for admin attempt %d", i))
		if err := store.Create(ctx, ev); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	other := mkEvent("sshd", "info", "Accepted publickey for carol")
	if err := store.Create(ctx, other); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := store.Search(ctx, events.Query{Text: "Failed"})
	if err != nil {
		t.Fatalf("FTS search errored: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("FTS: want 3 matches for %q, got %d", "Failed", len(got))
	}

	cnt, err := store.Count(ctx, events.Query{Text: "Failed"})
	if err != nil {
		t.Fatalf("FTS count errored: %v", err)
	}
	if cnt != 3 {
		t.Errorf("FTS count: want 3 got %d", cnt)
	}
}

func TestSearch_BareKeywordDoesNotError(t *testing.T) {
	// A detection query like "a=1 AND b=2" used to leak the literal token AND
	// into the FTS MATCH string, which is an FTS5 syntax error.
	store, cleanup := setupStore(t)
	defer cleanup()

	ev := mkEvent("auth", "err", "boom")
	if err := store.Create(context.Background(), ev); err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := store.Search(context.Background(), events.Query{Text: "AND"}); err != nil {
		t.Errorf("Search with literal keyword token errored: %v", err)
	}
}

func TestSearch_SortByInjectionRejected(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	ev := mkEvent("a", "info", "x")
	_ = store.Create(ctx, ev)

	malicious := []string{
		"timestamp,(SELECT id FROM events)",
		"CASE WHEN 1=1 THEN timestamp ELSE id END",
		"timestamp; DROP TABLE events; --",
	}
	for _, sb := range malicious {
		_, err := store.Search(ctx, events.Query{SortBy: sb})
		if err == nil {
			// Safe implementations either error or silently fall back to the
			// default column. Executing the expression raw is not acceptable.
			continue
		}
	}
	// After the call with an injection attempt, the table must still be intact.
	n, err := store.Count(ctx, events.Query{})
	if err != nil || n != 1 {
		t.Fatalf("data corrupted after injection attempt: n=%d err=%v", n, err)
	}

	// Explicitly verify non-whitelisted identifiers are not executed raw:
	// a raw-executed "(SELECT COUNT(*) FROM events)" as ORDER BY term parses and
	// would be accepted without error. We assert the store never echoes such SQL back
	// by checking a syntactically invalid column errors out.
	if _, err := store.Search(ctx, events.Query{SortBy: "nope nope nope(("}); err == nil {
		t.Errorf("expected error for garbage SortBy, got success (raw interpolation suspected)")
	}
}

func TestSearch_AndCountConsistency(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	for i := 0; i < 120; i++ {
		ev := mkEvent("auth", "err", fmt.Sprintf("failed login %d", i))
		ev.User = "mallory"
		if err := store.Create(ctx, ev); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}

	total, err := store.Count(ctx, events.Query{User: "mallory"})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if total != 120 {
		t.Errorf("Count with filters: want 120, got %d", total)
	}

	// Search default limit caps at 100, that is fine, but limit must be honored.
	got, err := store.Search(ctx, events.Query{User: "mallory", Limit: 500})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(got) != 120 {
		t.Errorf("Search limit 500: want 120 rows, got %d", len(got))
	}
}

func TestCreateBatch_AllRows(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	batch := make([]*event.Event, 0, 250)
	for i := 0; i < 250; i++ {
		ev := mkEvent("src", "info", "msg")
		ev.Attributes["idx"] = i
		batch = append(batch, ev)
	}
	if err := store.CreateBatch(ctx, batch); err != nil {
		t.Fatalf("CreateBatch: %v", err)
	}
	n, err := store.Count(ctx, events.Query{})
	if err != nil || n != 250 {
		t.Fatalf("want 250 rows, got %d (err %v)", n, err)
	}

	got, err := store.Search(ctx, events.Query{Limit: 300})
	if err != nil {
		t.Fatalf("search after batch: %v", err)
	}
	if got[0].Attributes == nil {
		t.Errorf("batched events lost attributes")
	}
}

func TestGetByID_NotFound(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	_, err := store.GetByID(context.Background(), "missing")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("want not-found error, got %v", err)
	}
	if _, err := store.GetByID(context.Background(), ""); err == nil {
		t.Errorf("want error for empty ID")
	}
}

func TestDeleteByID(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()
	ev := mkEvent("a", "info", "x")
	_ = store.Create(ctx, ev)
	if err := store.DeleteByID(ctx, ev.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := store.DeleteByID(ctx, ev.ID); err == nil {
		t.Errorf("want not-found on second delete")
	}
}

func TestBoundaries(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	// Huge message (1 MiB) and unicode content must survive round-trip.
	big := mkEvent("big", "info", strings.Repeat("あいう", 35000))
	if err := store.Create(ctx, big); err != nil {
		t.Fatalf("create big: %v", err)
	}
	got, err := store.GetByID(ctx, big.ID)
	if err != nil {
		t.Fatalf("get big: %v", err)
	}
	if len(got.Message) != len(big.Message) {
		t.Errorf("unicode message corrupted")
	}

	// Zero limit falls back to default instead of erroring.
	if _, err := store.Search(ctx, events.Query{Limit: 0}); err != nil {
		t.Errorf("limit 0 should default, got err %v", err)
	}
	if _, err := store.Search(ctx, events.Query{Offset: -5}); err != nil {
		t.Errorf("negative offset should clamp, got err %v", err)
	}
}

func TestTimeRangeFilters(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	base := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		ev := event.NewEvent()
		ev.Source = "t"
		ev.Severity = "info"
		ev.Message = "tick"
		ev.Timestamp = base.Add(time.Duration(i) * time.Hour)
		if err := store.Create(ctx, ev); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	start := base.Add(1 * time.Hour)
	end := base.Add(3 * time.Hour)
	n, err := store.Count(ctx, events.Query{Start: start, End: end})
	if err != nil {
		t.Fatalf("count range: %v", err)
	}
	if n != 3 {
		t.Errorf("time window: want 3 got %d", n)
	}
}
