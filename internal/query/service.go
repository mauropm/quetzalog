// Package query provides the top-level search service used by the HTTP API. It
// intentionally holds no query engine of its own: every search is executed by the
// single SPL pipeline in internal/spl/executor, so the search bar and the SPL
// builder share one parser, one planner and one executor.
package query

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"quetzalog/internal/spl/executor"
	"quetzalog/pkg/event"
)

// Service handles search query parsing and execution.
type Service struct {
	db *sql.DB
}

// SearchRequest represents a search query request.
type SearchRequest struct {
	Query    string
	Earliest string
	Latest   string
	Limit    int
	Offset   int
}

// SearchResponse represents the result of a search query.
type SearchResponse struct {
	Columns []string
	Results []map[string]any
	Count   int
}

// NewService creates a new query service backed by the given database.
func NewService(db *sql.DB) *Service {
	return &Service{db: db}
}

// maxServiceLimit bounds result sets requested through the search service.
const maxServiceLimit = 1000

// Execute parses a search query and returns matching events. The query is run
// through the SPL pipeline; the only service-owned behavior is argument clamping,
// relative/absolute time resolution and the no-query dashboard summary.
func (s *Service) Execute(ctx context.Context, req SearchRequest) (*SearchResponse, error) {
	if req.Limit <= 0 {
		req.Limit = 100
	}
	if req.Limit > maxServiceLimit {
		req.Limit = maxServiceLimit
	}
	if req.Offset < 0 {
		req.Offset = 0
	}

	trimmed := strings.TrimSpace(req.Query)
	if trimmed == "" && req.Earliest == "" && req.Latest == "" {
		return s.executeEmptyQuery(ctx, req)
	}

	var earliest, latest time.Time
	if req.Earliest != "" {
		t, ok := parseTimeBound(req.Earliest)
		if !ok {
			return nil, fmt.Errorf("invalid earliest time %q", req.Earliest)
		}
		earliest = t
	}
	if req.Latest != "" {
		t, ok := parseTimeBound(req.Latest)
		if !ok {
			return nil, fmt.Errorf("invalid latest time %q", req.Latest)
		}
		latest = t
	}

	res, err := executor.Run(ctx, s.db, req.Query, executor.RunOptions{
		Limit:    req.Limit,
		Offset:   req.Offset,
		Earliest: earliest,
		Latest:   latest,
	})
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	cols := res.Columns
	if cols == nil {
		cols = []string{}
	}
	rows := res.Rows
	if rows == nil {
		rows = []map[string]any{}
	}
	return &SearchResponse{Columns: cols, Results: rows, Count: res.Count}, nil
}

// executeEmptyQuery returns a basic aggregation when no query is provided.
func (s *Service) executeEmptyQuery(ctx context.Context, req SearchRequest) (*SearchResponse, error) {
	query := `SELECT COUNT(*) as total_count,
	            COUNT(DISTINCT source) as source_count,
	            COUNT(DISTINCT host) as host_count,
	            COUNT(DISTINCT severity) as severity_count
	      FROM events`

	var where []string
	var args []any
	if req.Earliest != "" {
		t, ok := parseTimeBound(req.Earliest)
		if !ok {
			return nil, fmt.Errorf("invalid earliest time %q", req.Earliest)
		}
		where = append(where, "timestamp >= ?")
		args = append(args, t)
	}
	if req.Latest != "" {
		t, ok := parseTimeBound(req.Latest)
		if !ok {
			return nil, fmt.Errorf("invalid latest time %q", req.Latest)
		}
		where = append(where, "timestamp <= ?")
		args = append(args, t)
	}
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}

	row := s.db.QueryRowContext(ctx, query, args...)
	var totalCount, sourceCount, hostCount, severityCount int
	err := row.Scan(&totalCount, &sourceCount, &hostCount, &severityCount)
	if err != nil {
		return nil, fmt.Errorf("count query: %w", err)
	}

	return &SearchResponse{
		Columns: []string{"total_count", "source_count", "host_count", "severity_count"},
		Results: []map[string]any{
			{
				"total_count":    totalCount,
				"source_count":   sourceCount,
				"host_count":     hostCount,
				"severity_count": severityCount,
			},
		},
		Count: totalCount,
	}, nil
}

// parseTimeBound resolves an absolute (RFC3339/unix) or relative ("24h","-7d",
// "now") time bound to a concrete timestamp. ok=false means the value could not
// be understood. Relative bounds are subtracted from the current time.
func parseTimeBound(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, true
	}
	if strings.EqualFold(s, "now") {
		return time.Now(), true
	}
	if d, ok := parseRelativeDuration(s); ok {
		return time.Now().Add(-d), true
	}
	t := event.ParseTimestamp(s)
	return t, !t.IsZero()
}

// parseRelativeDuration understands Splunk-style ranges: 24h, 30m, 7d, 2w,
// 45s (optionally with a leading '-'), plus plain Go durations like 2h30m.
func parseRelativeDuration(s string) (time.Duration, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "-")
	if s == "" || strings.EqualFold(s, "all") {
		return 0, false
	}
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}
	numPart, unit := s[:i], strings.ToLower(s[i:])
	if numPart == "" {
		return 0, false
	}
	n, err := strconv.ParseFloat(numPart, 64)
	if err != nil {
		// Not a "<number><unit>" form; try a whole Go duration (e.g. 2h30m).
		if d, e2 := time.ParseDuration(s); e2 == nil {
			return d, true
		}
		return 0, false
	}
	switch unit {
	case "s", "sec", "secs", "second", "seconds":
		return time.Duration(n * float64(time.Second)), true
	case "m", "min", "mins", "minute", "minutes":
		return time.Duration(n * float64(time.Minute)), true
	case "h", "hr", "hrs", "hour", "hours":
		return time.Duration(n * float64(time.Hour)), true
	case "d", "day", "days":
		return time.Duration(n * 24 * float64(time.Hour)), true
	case "w", "week", "weeks":
		return time.Duration(n * 7 * 24 * float64(time.Hour)), true
	case "":
		if d, e2 := time.ParseDuration(s); e2 == nil {
			return d, true
		}
	}
	return 0, false
}
