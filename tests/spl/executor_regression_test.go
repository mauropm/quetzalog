package spl

import (
	"context"
	"strings"
	"testing"

	"quetzalog/internal/spl/executor"
)

// search "*" used to compile to an empty FTS MATCH and silently return zero
// rows; it must now return everything.
func TestRegression_SearchStarReturnsAllRows(t *testing.T) {
	res := run(t, `search *`, 10)
	if res.Count != 4 {
		t.Fatalf("expected 4 rows for `search *`, got %d", res.Count)
	}
}

// `where` after `stats` filters the aggregate output in memory; it must not
// be pushed into the SQL WHERE clause (where the aggregate field does not
// exist).
func TestRegression_PostAggWhere(t *testing.T) {
	res := run(t, `stats count by user | where count > 1`, 10)
	if res.Count != 1 {
		t.Fatalf("expected 1 aggregate row with count>1, got %d", res.Count)
	}
	row := res.Rows[0]
	if row["user"] != "mauro" {
		t.Errorf("expected user mauro, got %v", row["user"])
	}
}

// The API path runs with RunOptions{Limit:0}; runRows used to emit LIMIT 0
// in that case and return nothing. The clamped default (100) must apply.
func TestRegression_ZeroLimitReturnsRows(t *testing.T) {
	db := newExecutorDB(t)
	res, err := executor.Run(context.Background(), db, `where host="web-01"`, executor.RunOptions{Limit: 0})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Count != 2 {
		t.Fatalf("expected 2 rows with Limit:0, got %d", res.Count)
	}
}

func TestRegression_BinIsExplicitError(t *testing.T) {
	db := newExecutorDB(t)
	_, err := executor.Run(context.Background(), db, `source=auth | bin timestamp span=1h`, executor.RunOptions{Limit: 10})
	if err == nil {
		t.Fatal("expected bin to return an error, got nil result")
	}
	if !strings.Contains(err.Error(), "bin") {
		t.Errorf("error should mention `bin`, got: %v", err)
	}
}

func TestRegression_LookupIsExplicitError(t *testing.T) {
	db := newExecutorDB(t)
	_, err := executor.Run(context.Background(), db, `source=auth | lookup geoip user output country`, executor.RunOptions{Limit: 10})
	if err == nil {
		t.Fatal("expected lookup to return an error, got nil result")
	}
	if !strings.Contains(err.Error(), "lookup") {
		t.Errorf("error should mention `lookup`, got: %v", err)
	}
}

// max()/min() without arguments indexed args[0] and panicked the test
// process (and any server) before the length guard.
func TestRegression_MaxMinNoArgsNoPanic(t *testing.T) {
	db := newExecutorDB(t)
	res, err := executor.Run(context.Background(), db, `| eval m=max()`, executor.RunOptions{Limit: 10})
	if err != nil {
		t.Fatalf("max() without args should not error out of the query, got: %v", err)
	}
	if res.Count != 4 {
		t.Fatalf("expected 4 rows, got %d", res.Count)
	}
}
