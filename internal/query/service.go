package query

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"quetzalog/internal/events"
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

var (
	validKeyRe = regexp.MustCompile(`^[a-z0-9_]+$`)
	statsByRe  = regexp.MustCompile(`(?i)\bby\s+([a-z0-9_]+)`)
)

// maxServiceLimit bounds result sets requested through the search service.
const maxServiceLimit = 1000

// Execute parses a search query and returns matching events.
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

	parts := strings.Split(req.Query, "|")
	baseQuery := strings.TrimSpace(parts[0])
	var pipeCommands []string
	for i := 1; i < len(parts); i++ {
		pipeCommands = append(pipeCommands, strings.TrimSpace(parts[i]))
	}

	if baseQuery == "" && req.Earliest == "" && req.Latest == "" && len(pipeCommands) == 0 {
		return s.executeEmptyQuery(ctx, req)
	}

	q, err := s.buildEventQuery(baseQuery, req.Earliest, req.Latest, req.Limit, req.Offset)
	if err != nil {
		return nil, fmt.Errorf("build event query: %w", err)
	}

	store := events.NewStore(s.db)

	// A stats pipeline aggregates the returned rows in process and reports the
	// number of groups, so the total row count would be computed and thrown
	// away. Skip it for that path.
	if hasStats(pipeCommands) {
		evts, err := store.Search(ctx, q)
		if err != nil {
			return nil, fmt.Errorf("search events: %w", err)
		}
		return s.applyStats(evts, pipeCommands), nil
	}

	total, err := store.Count(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("count events: %w", err)
	}

	evts, err := store.Search(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("search events: %w", err)
	}

	evts = s.applySort(evts, pipeCommands)
	evts = s.applyHead(evts, pipeCommands)
	resp := s.toResponse(evts, total)

	return resp, nil
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
		t, err := event.ParseTimestamp(req.Earliest), error(nil)
		if t.IsZero() {
			return nil, fmt.Errorf("invalid earliest time %q", req.Earliest)
		}
		_ = err
		where = append(where, "timestamp >= ?")
		args = append(args, t)
	}
	if req.Latest != "" {
		t := event.ParseTimestamp(req.Latest)
		if t.IsZero() {
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

	resp := &SearchResponse{
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
	}

	return resp, nil
}

// buildEventQuery converts a base query string and time params into events.Query params.
func (s *Service) buildEventQuery(baseQuery, earliest, latest string, limit, offset int) (events.Query, error) {
	q := events.Query{
		Limit:      limit,
		Offset:     offset,
		SortBy:     "timestamp",
		SortOrder:  "desc",
		Attributes: make(map[string]string),
	}

	fieldValues := make(map[string][]string)
	var bareTerms []string

	for _, part := range strings.Fields(baseQuery) {
		switch strings.ToUpper(part) {
		case "OR", "AND":
			continue
		}
		idx := strings.Index(part, "=")
		if idx <= 0 {
			bareTerms = append(bareTerms, part)
			continue
		}
		key := strings.ToLower(strings.TrimSpace(part[:idx]))
		value := strings.TrimSpace(part[idx+1:])
		if !validKeyRe.MatchString(key) {
			return q, fmt.Errorf("invalid query field %q", key)
		}
		fieldValues[key] = append(fieldValues[key], value)
	}

	for _, term := range bareTerms {
		if q.Text == "" {
			q.Text = term
		} else {
			q.Text += " " + term
		}
	}

	for key, values := range fieldValues {
		col := normalizeSearchField(key)
		if col == "" {
			for _, value := range values {
				if !validKeyRe.MatchString(key) {
					return q, fmt.Errorf("invalid attribute key %q", key)
				}
				q.Attributes[key] = value
			}
			continue
		}
		if len(values) == 1 {
			setQueryField(&q, col, values[0])
			continue
		}
		q.Attributes["__or_"+col+"__"] = strings.Join(values, ",")
	}

	if earliest != "" {
		t := event.ParseTimestamp(earliest)
		if t.IsZero() {
			return q, fmt.Errorf("invalid earliest time %q", earliest)
		}
		q.Start = t
	}
	if latest != "" {
		t := event.ParseTimestamp(latest)
		if t.IsZero() {
			return q, fmt.Errorf("invalid latest time %q", latest)
		}
		q.End = t
	}

	return q, nil
}

func normalizeSearchField(key string) string {
	switch key {
	case "source":
		return "source"
	case "event_type", "eventtype":
		return "event_type"
	case "host":
		return "host"
	case "service":
		return "service"
	case "severity", "sev":
		return "severity"
	case "category":
		return "category"
	case "action":
		return "action"
	case "outcome":
		return "outcome"
	case "user":
		return "user"
	case "source_ip", "src_ip", "sourceip":
		return "source_ip"
	case "destination_ip", "dest_ip", "destnation_ip", "destinationip":
		return "destination_ip"
	default:
		return ""
	}
}

func setQueryField(q *events.Query, col, value string) {
	switch col {
	case "source":
		q.Source = value
	case "event_type":
		q.EventType = value
	case "host":
		q.Host = value
	case "service":
		q.Service = value
	case "severity":
		q.Severity = value
	case "category":
		q.Category = value
	case "action":
		q.Action = value
	case "outcome":
		q.Outcome = value
	case "user":
		q.User = value
	case "source_ip":
		q.SourceIP = value
	case "destination_ip":
		q.DestinationIP = value
	}
}

// hasStats checks if any pipe command is a stats command.
func hasStats(cmds []string) bool {
	for _, c := range cmds {
		if strings.HasPrefix(strings.TrimSpace(c), "stats") {
			return true
		}
	}
	return false
}

// applyStats applies the stats count by aggregation.
func (s *Service) applyStats(events []*event.Event, cmds []string) *SearchResponse {
	byCol := ""
	for _, c := range cmds {
		trimmed := strings.TrimSpace(c)
		if strings.HasPrefix(trimmed, "stats") {
			if by := extractStatsBy(trimmed); by != "" {
				byCol = by
			}
		}
	}

	groups := make(map[string]int)
	for _, ev := range events {
		var key string
		switch byCol {
		case "source":
			key = ev.Source
		case "host":
			key = ev.Host
		case "severity":
			key = ev.Severity
		case "event_type", "eventtype":
			key = ev.EventType
		case "category":
			key = ev.Category
		case "action":
			key = ev.Action
		case "user":
			key = ev.User
		case "service":
			key = ev.Service
		default:
			key = ev.ID
		}
		groups[key]++
	}

	cols := []string{byCol, "count"}
	results := make([]map[string]any, 0, len(groups))

	type groupCount struct {
		key   string
		count int
	}
	var sorted []groupCount
	for k, v := range groups {
		sorted = append(sorted, groupCount{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].count != sorted[j].count {
			return sorted[i].count > sorted[j].count
		}
		return sorted[i].key < sorted[j].key
	})

	for _, g := range sorted {
		results = append(results, map[string]any{
			byCol:   g.key,
			"count": g.count,
		})
	}

	return &SearchResponse{
		Columns: cols,
		Results: results,
		Count:   len(results),
	}
}

// extractStatsBy extracts the "by X" part from a stats command.
func extractStatsBy(cmd string) string {
	matches := statsByRe.FindStringSubmatch(cmd)
	if len(matches) >= 2 {
		return strings.ToLower(matches[1])
	}
	return ""
}

// applySort applies sort commands to the events.
func (s *Service) applySort(events []*event.Event, cmds []string) []*event.Event {
	for _, c := range cmds {
		trimmed := strings.TrimSpace(c)
		if !strings.HasPrefix(trimmed, "sort") {
			continue
		}

		var sortCol string
		desc := false

		rest := strings.TrimSpace(trimmed[len("sort"):])
		if strings.HasPrefix(rest, "-") {
			sortCol = strings.TrimSpace(rest[1:])
			desc = true
		} else if fields := strings.Fields(rest); len(fields) > 0 {
			sortCol = strings.ToLower(fields[0])
		}
		if sortCol == "" {
			continue
		}

		sort.Slice(events, func(i, j int) bool {
			var vi, vj any
			switch sortCol {
			case "timestamp":
				vi = events[i].Timestamp
				vj = events[j].Timestamp
			case "severity":
				vi = event.ParseSeverity(events[i].Severity)
				vj = event.ParseSeverity(events[j].Severity)
			case "source":
				vi = events[i].Source
				vj = events[j].Source
			case "host":
				vi = events[i].Host
				vj = events[j].Host
			case "event_type", "eventtype":
				vi = events[i].EventType
				vj = events[j].EventType
			case "message":
				vi = events[i].Message
				vj = events[j].Message
			case "user":
				vi = events[i].User
				vj = events[j].User
			default:
				vi = events[i].ID
				vj = events[j].ID
			}

			if desc {
				return compareValues(vj, vi) < 0
			}
			return compareValues(vi, vj) < 0
		})
	}

	return events
}

// compareValues compares two values for sorting.
func compareValues(a, b any) int {
	if ta, ok := a.(time.Time); ok {
		if tb, ok := b.(time.Time); ok {
			if ta.Before(tb) {
				return -1
			}
			if ta.After(tb) {
				return 1
			}
			return 0
		}
	}

	if sa, ok := a.(string); ok {
		if sb, ok := b.(string); ok {
			return strings.Compare(sa, sb)
		}
	}

	if na, ok := a.(int); ok {
		if nb, ok := b.(int); ok {
			if na < nb {
				return -1
			}
			if na > nb {
				return 1
			}
			return 0
		}
	}

	if fa, ok := a.(float64); ok {
		if fb, ok := b.(float64); ok {
			if fa < fb {
				return -1
			}
			if fa > fb {
				return 1
			}
			return 0
		}
	}

	return strings.Compare(fmt.Sprintf("%v", a), fmt.Sprintf("%v", b))
}

// applyHead applies the head N command (limit).
func (s *Service) applyHead(events []*event.Event, cmds []string) []*event.Event {
	for _, c := range cmds {
		trimmed := strings.TrimSpace(c)
		if !strings.HasPrefix(trimmed, "head") {
			continue
		}
		parts := strings.Fields(trimmed)
		if len(parts) < 2 {
			continue
		}
		n, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		if n < 0 {
			n = 0
		}
		if n > len(events) {
			n = len(events)
		}
		return events[:n]
	}
	return events
}

// toResponse converts a list of events to a SearchResponse with columnar data.
func (s *Service) toResponse(events []*event.Event, total int) *SearchResponse {
	if events == nil {
		events = []*event.Event{}
	}

	cols := []string{"id", "timestamp", "source", "severity", "event_type", "host", "message"}
	results := make([]map[string]any, len(events))

	// The projected columns are a small fixed subset of the canonical event.
	// Reading them straight off the struct avoids materialising the full
	// storage map (including a JSON re-encode of attributes) per row just to
	// copy seven values out of it.
	for i, ev := range events {
		results[i] = map[string]any{
			"id":         ev.ID,
			"timestamp":  ev.Timestamp.UTC(),
			"source":     ev.Source,
			"severity":   event.ParseSeverity(ev.Severity),
			"event_type": ev.EventType,
			"host":       ev.Host,
			"message":    ev.Message,
		}
	}

	return &SearchResponse{
		Columns: cols,
		Results: results,
		Count:   total,
	}
}
