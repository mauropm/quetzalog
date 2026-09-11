package query_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"quetzalog/internal/query"
)

// TestExecute_UnifiedSPLPipeline proves the search bar now runs the full SPL
// pipeline (stats, eval, sort, head, table), not the old | -split subset.
func TestExecute_UnifiedSPLPipeline(t *testing.T) {
	svc, db := setup(t)
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	seed(t, db, 9, base)

	resp, err := svc.Execute(context.Background(), query.SearchRequest{
		Query: `source=src0 OR source=src1 | eval sev=severity | table source,sev | sort source | head 2`,
		Limit: 50,
	})
	if err != nil {
		t.Fatalf("unified pipeline errored: %v", err)
	}
	if len(resp.Results) == 0 {
		t.Fatal("expected rows from pipeline")
	}
	if len(resp.Results) > 2 {
		t.Fatalf("head 2 not honored: %d rows", len(resp.Results))
	}
	// table projection produced exactly the requested columns.
	if len(resp.Columns) != 2 || resp.Columns[0] != "source" || resp.Columns[1] != "sev" {
		t.Fatalf("unexpected projection columns: %v", resp.Columns)
	}
}

func TestExecute_RelativeTimeExcludesOldEvents(t *testing.T) {
	svc, db := setup(t)
	// Seed events far in the past (2026 fixed) so a "1h" relative window from
	// now (2026-09 in CI, but relative to time.Now) excludes them.
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	seed(t, db, 5, base)

	resp, err := svc.Execute(context.Background(), query.SearchRequest{
		Query:    "source=src0 OR source=src1 OR source=src2",
		Earliest: "1h",
		Latest:   "now",
		Limit:    50,
	})
	if err != nil {
		t.Fatalf("relative range errored: %v", err)
	}
	if resp.Count != 0 {
		t.Fatalf("expected 0 rows in last-hour window, got %d", resp.Count)
	}

	// A wide relative window (1000000d) must include them again.
	resp2, err := svc.Execute(context.Background(), query.SearchRequest{
		Query:    "source=src0 OR source=src1 OR source=src2",
		Earliest: "1000000d",
		Latest:   "now",
		Limit:    50,
	})
	if err != nil {
		t.Fatalf("wide relative range errored: %v", err)
	}
	if resp2.Count != 5 {
		t.Fatalf("expected 5 rows in wide window, got %d", resp2.Count)
	}
}

func TestExecute_BadSPLIsClientError(t *testing.T) {
	svc, db := setup(t)
	seed(t, db, 2, time.Now())
	_, err := svc.Execute(context.Background(), query.SearchRequest{Query: "search ]", Limit: 10})
	if err == nil {
		t.Fatal("expected error for lexically invalid query")
	}
	if !strings.Contains(err.Error(), "invalid spl query") && !strings.Contains(err.Error(), "unexpected character") {
		t.Fatalf("expected a user-facing error, got: %v", err)
	}
}
