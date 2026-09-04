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

// Execute parses a search query and returns matching events.
func (s *Service) Execute(ctx context.Context, req SearchRequest) (*SearchResponse, error) {
	if req.Limit <= 0 {
		req.Limit = 100
	}
	if req.Offset < 0 {
		req.Offset = 0
	}

	// If no query, return count and basic aggregation
	if req.Query == "" {
		return s.executeEmptyQuery(ctx, req)
	}

	// Parse the query by pipe
	parts := strings.Split(req.Query, "|")

	// First part: build base filter
	baseQuery := strings.TrimSpace(parts[0])

	// Parse remaining pipe commands
	var pipeCommands []string
	for i := 1; i < len(parts); i++ {
		pipeCommands = append(pipeCommands, strings.TrimSpace(parts[i]))
	}

	// Build events.Search query from base query
	evQuery, err := s.buildEventQuery(baseQuery, req.Earliest, req.Latest, req.Limit, req.Offset)
	if err != nil {
		return nil, fmt.Errorf("build event query: %w", err)
	}

	// Fetch events from the events store using raw SQL
	evts, err := s.searchEvents(ctx, evQuery)
	if err != nil {
		return nil, fmt.Errorf("search events: %w", err)
	}

	total := len(evts)

	// Apply pipe commands
	// First apply stats (aggregation)
	if hasStats(pipeCommands) {
		return s.applyStats(evts, pipeCommands), nil
	}

	// Apply sort
	evts = s.applySort(evts, pipeCommands)

	// Apply head (limit)
	evts = s.applyHead(evts, pipeCommands)

	// Convert to columnar format
	resp := s.toResponse(evts, total)

	// Apply offset to response
	if req.Offset > 0 && len(resp.Results) > req.Offset {
		resp.Results = resp.Results[req.Offset:]
	}

	return resp, nil
}

// executeEmptyQuery returns a basic aggregation when no query is provided.
func (s *Service) executeEmptyQuery(ctx context.Context, req SearchRequest) (*SearchResponse, error) {
	query := `SELECT COUNT(*) as total_count,
	            COUNT(DISTINCT source) as source_count,
	            COUNT(DISTINCT host) as host_count,
	            COUNT(DISTINCT severity) as severity_count
	      FROM events`

	if req.Earliest != "" {
		query += fmt.Sprintf(" AND timestamp >= '%s'", req.Earliest)
	}
	if req.Latest != "" {
		query += fmt.Sprintf(" AND timestamp <= '%s'", req.Latest)
	}

	row := s.db.QueryRowContext(ctx, query)
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

// buildEventQuery converts a base query string and time params into an events.Search query params.
func (s *Service) buildEventQuery(baseQuery, earliest, latest string, limit, offset int) (map[string]any, error) {
	params := map[string]any{
		"limit":  limit,
		"offset": offset,
	}

	if baseQuery == "" {
		return params, nil
	}

	// Parse key=value pairs from the base query
	filter := eventsFilter(baseQuery)
	if len(filter) > 0 {
		params["filter"] = filter
	}

	return params, nil
}

// eventsFilter parses key=value filters from a query string.
func eventsFilter(q string) map[string]string {
	filter := make(map[string]string)
	parts := strings.Fields(q)

	for _, part := range parts {
		if idx := strings.Index(part, "="); idx > 0 {
			key := strings.ToLower(strings.TrimSpace(part[:idx]))
			value := strings.TrimSpace(part[idx+1:])

			switch key {
			case "source":
				filter["source"] = value
			case "event_type", "eventtype":
				filter["event_type"] = value
			case "host":
				filter["host"] = value
			case "service":
				filter["service"] = value
			case "severity", "sev":
				filter["severity"] = value
			case "category":
				filter["category"] = value
			case "action":
				filter["action"] = value
			case "user":
				filter["user"] = value
			default:
				filter[key] = value
			}
		}
	}

	return filter
}

// searchEvents executes a search against the events table.
func (s *Service) searchEvents(ctx context.Context, params map[string]any) ([]*event.Event, error) {
	baseSQL := `SELECT id, timestamp, received_at, source, source_type, host, ip, service,
	            application, severity, message, event_type, category, action, outcome,
	            user, user_id, process, process_id, parent_pid, file_path,
	            destination_ip, destination_port, source_ip, source_port,
	            raw, raw_format, trace_id, span_id, attributes
	      FROM events`

	var whereClauses []string
	var args []any

	if filter, ok := params["filter"].(map[string]string); ok {
		for col, val := range filter {
			whereClauses = append(whereClauses, fmt.Sprintf("%s = ?", col))
			args = append(args, val)
		}
	}

	if len(whereClauses) > 0 {
		baseSQL += " WHERE " + strings.Join(whereClauses, " AND ")
	}

	limit, _ := params["limit"].(int)
	offset, _ := params["offset"].(int)
	if limit <= 0 {
		limit = 100
	}
	baseSQL += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT %d", limit)
	if offset > 0 {
		baseSQL += fmt.Sprintf(" OFFSET %d", offset)
	}

	rows, err := s.db.QueryContext(ctx, baseSQL, args...)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var evts []*event.Event
	for rows.Next() {
		ev := &event.Event{}
		err := rows.Scan(
			&ev.ID, &ev.Timestamp, &ev.ReceivedAt, &ev.Source, &ev.SourceType,
			&ev.Host, &ev.IP, &ev.Service, &ev.Application, &ev.Severity,
			&ev.Message, &ev.EventType, &ev.Category, &ev.Action, &ev.Outcome,
			&ev.User, &ev.UserID, &ev.Process, &ev.ProcessID, &ev.ParentPID,
			&ev.FilePath, &ev.DestinationIP, &ev.DestinationPort, &ev.SourceIP,
			&ev.SourcePort,
			nil, // raw (skip)
			&ev.RawFormat, &ev.TraceID, &ev.SpanID,
			nil, // attributes (skip)
		)
		if err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		evts = append(evts, ev)
	}

	return evts, nil
}

// hasStats checks if any pipe command is a stats command.
func hasStats(cmds []string) bool {
	for _, c := range cmds {
		trimmed := strings.TrimSpace(c)
		if strings.HasPrefix(trimmed, "stats") {
			return true
		}
	}
	return false
}

// applyStats applies the stats count by aggregation.
func (s *Service) applyStats(events []*event.Event, cmds []string) *SearchResponse {
	// Find the stats by column
	byCol := ""
	for _, c := range cmds {
		trimmed := strings.TrimSpace(c)
		if strings.HasPrefix(trimmed, "stats") {
			by := extractStatsBy(trimmed)
			if by != "" {
				byCol = by
			}
		}
	}

	// Group by column and count
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
		case "event_type":
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
			// Use message or id as default
			key = ev.ID
		}
		groups[key]++
	}

	// Build results
	cols := []string{byCol, "count"}
	results := make([]map[string]any, 0, len(groups))

	// Sort by count descending
	type groupCount struct {
		key   string
		count int
	}
	var sorted []groupCount
	for k, v := range groups {
		sorted = append(sorted, groupCount{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
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
	// Match "stats count by X" or "stats X by Y"
	re := regexp.MustCompile(`(?i)\bby\s+(\w+)`)
	matches := re.FindStringSubmatch(cmd)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

// applySort applies sort commands to the events.
func (s *Service) applySort(events []*event.Event, cmds []string) []*event.Event {
	for _, c := range cmds {
		trimmed := strings.TrimSpace(c)
		if strings.HasPrefix(trimmed, "sort") {
			desc := false
			sortCol := ""

			parts := strings.Fields(trimmed)
			for i, p := range parts {
				if p == "-sort" || p == "sort" {
					if i+1 < len(parts) {
						sortCol = parts[i+1]
						break
					}
				}
				if p == "-sort" || p == "-1" || p == "-desc" {
					desc = true
				}
			}

			// Check for explicit -X (descending)
			if sortCol == "" {
				re := regexp.MustCompile(`(?i)^sort\s*-(\w+)`)
				matches := re.FindStringSubmatch(trimmed)
				if len(matches) >= 2 {
					sortCol = matches[1]
					desc = true
				} else {
					re = regexp.MustCompile(`(?i)^sort\s+(\w+)`)
					matches = re.FindStringSubmatch(trimmed)
					if len(matches) >= 2 {
						sortCol = matches[1]
					}
				}
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
				default:
					vi = events[i].ID
					vj = events[j].ID
				}

				if desc {
					return compareValues(vj, vi) > 0
				}
				return compareValues(vi, vj) > 0
			})
		}
	}

	return events
}

// compareValues compares two values for sorting.
func compareValues(a, b any) int {
	// Handle time.Time
	if ta, ok := a.(interface{ Before(time.Time) bool }); ok {
		if tb, ok := b.(time.Time); ok {
			if ta.(time.Time).Before(tb) {
				return -1
			}
			if ta.(time.Time).After(tb) {
				return 1
			}
			return 0
		}
	}

	// Handle strings
	if sa, ok := a.(string); ok {
		if sb, ok := b.(string); ok {
			return strings.Compare(sa, sb)
		}
	}

	// Handle numbers
	if na, ok := a.(int); ok {
		if nb, ok := b.(int); ok {
			return na - nb
		}
	}

	// Handle float64
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

	// Default: compare as strings
	return strings.Compare(fmt.Sprintf("%v", a), fmt.Sprintf("%v", b))
}

// applyHead applies the head N command (limit).
func (s *Service) applyHead(events []*event.Event, cmds []string) []*event.Event {
	for _, c := range cmds {
		trimmed := strings.TrimSpace(c)
		if strings.HasPrefix(trimmed, "head") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				n, err := strconv.Atoi(parts[1])
				if err == nil && n < len(events) {
					return events[:n]
				}
			}
		}
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

	for i, ev := range events {
		m := event.EventToMap(ev)
		row := make(map[string]any)
		for _, col := range cols {
			if v, ok := m[col]; ok {
				row[col] = v
			} else {
				row[col] = ""
			}
		}
		results[i] = row
	}

	return &SearchResponse{
		Columns: cols,
		Results: results,
		Count:   total,
	}
}
