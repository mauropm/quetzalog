package events

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"quetzalog/pkg/event"
)

// Store persists events to a SQLite database with FTS5 full-text search support.
type Store struct {
	db *sql.DB
}

// NewStore creates a new event store backed by the given database connection.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// Create inserts a single event into the database.
func (s *Store) Create(ctx context.Context, ev *event.Event) error {
	if ev == nil {
		return fmt.Errorf("nil event provided")
	}

	m := event.EventToMap(ev)

	// Build column list and placeholders from the map keys in a deterministic order.
	cols, vals, placeholders := mapToInsert(m)

	q := fmt.Sprintf("INSERT INTO events (%s) VALUES (%s)",
		strings.Join(cols, ", "),
		strings.Join(placeholders, ", "),
	)

	_, err := s.db.ExecContext(ctx, q, vals...)
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}

	return nil
}

// CreateBatch inserts multiple events in a single transaction.
func (s *Store) CreateBatch(ctx context.Context, events []*event.Event) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin batch transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, batchInsertTemplate())
	if err != nil {
		return fmt.Errorf("prepare batch insert: %w", err)
	}
	defer stmt.Close()

	for _, ev := range events {
		if ev == nil {
			continue
		}
		m := event.EventToMap(ev)
		values := make([]any, 0, len(m))
		for _, col := range insertColumnOrder {
			if v, ok := m[col]; ok {
				values = append(values, v)
			} else {
				values = append(values, nil)
			}
		}
		if _, err := stmt.ExecContext(ctx, values...); err != nil {
			return fmt.Errorf("batch insert event %s: %w", ev.ID, err)
		}
	}

	return tx.Commit()
}

// GetByID retrieves a single event by its ID.
func (s *Store) GetByID(ctx context.Context, id string) (*event.Event, error) {
	if id == "" {
		return nil, fmt.Errorf("empty event ID")
	}

	q := `SELECT id, timestamp, received_at, source, source_type, host, ip, service,
	            application, severity, message, event_type, category, action, outcome,
	            user, user_id, process, process_id, parent_pid, file_path,
	            destination_ip, destination_port, source_ip, source_port,
	            raw, raw_format, trace_id, span_id, attributes
	     FROM events WHERE id = ?`

	ev, err := scanEventRow(s.db.QueryRowContext(ctx, q, id))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("event %s not found", id)
		}
		return nil, fmt.Errorf("query event %s: %w", id, err)
	}

	return ev, nil
}

// Search returns events matching the given query criteria.
// Text matching uses the FTS5 events_fts virtual table.
func (s *Store) Search(ctx context.Context, q Query) ([]*event.Event, error) {
	if q.Limit <= 0 {
		q.Limit = 100
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	if q.SortBy == "" {
		q.SortBy = "timestamp"
	}
	if q.SortOrder == "" || (q.SortOrder != "asc" && q.SortOrder != "desc") {
		q.SortOrder = "desc"
	}

	sqlParts, args, err := buildSearchQuery(q)
	if err != nil {
		return nil, fmt.Errorf("build search query: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, sqlParts, args...)
	if err != nil {
		return nil, fmt.Errorf("execute search: %w", err)
	}
	defer rows.Close()

	var events []*event.Event
	for rows.Next() {
		ev, err := scanEventRow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan event row: %w", err)
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate search results: %w", err)
	}

	if events == nil {
		events = []*event.Event{}
	}

	return events, nil
}

// Count returns the total number of events matching the query criteria.
func (s *Store) Count(ctx context.Context, q Query) (int, error) {
	sqlParts, args, err := buildSearchQuery(q)
	if err != nil {
		return 0, fmt.Errorf("build count query: %w", err)
	}

	// Replace SELECT ... FROM with SELECT COUNT(*) FROM while keeping WHERE/ORDER/LIMIT intact.
	countSQL := rewriteToCount(sqlParts)

	var total int
	err = s.db.QueryRowContext(ctx, countSQL, args...).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("count events: %w", err)
	}

	return total, nil
}

// DeleteByID removes a single event by its ID.
func (s *Store) DeleteByID(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("empty event ID")
	}

	result, err := s.db.ExecContext(ctx, "DELETE FROM events WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete event %s: %w", id, err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected for delete: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("event %s not found", id)
	}

	return nil
}

// scanEventRow reads a single database row into an event.Event.
func scanEventRow(row rowScanner) (*event.Event, error) {
	var ev event.Event
	var raw *[]byte
	var attrs *map[string]any

	err := row.Scan(
		&ev.ID,
		&ev.Timestamp,
		&ev.ReceivedAt,
		&ev.Source,
		&ev.SourceType,
		&ev.Host,
		&ev.IP,
		&ev.Service,
		&ev.Application,
		&ev.Severity,
		&ev.Message,
		&ev.EventType,
		&ev.Category,
		&ev.Action,
		&ev.Outcome,
		&ev.User,
		&ev.UserID,
		&ev.Process,
		&ev.ProcessID,
		&ev.ParentPID,
		&ev.FilePath,
		&ev.DestinationIP,
		&ev.DestinationPort,
		&ev.SourceIP,
		&ev.SourcePort,
		&raw,
		&ev.RawFormat,
		&ev.TraceID,
		&ev.SpanID,
		&attrs,
	)
	if err != nil {
		return nil, fmt.Errorf("scan event: %w", err)
	}

	if raw != nil {
		ev.Raw = *raw
	}
	if attrs != nil {
		ev.Attributes = *attrs
	} else {
		ev.Attributes = make(map[string]any)
	}

	return &ev, nil
}

// rowScanner is a common interface for sql.Row and sql.Rows Scan methods.
type rowScanner interface {
	Scan(dest ...any) error
}

// mapToInsert converts a map of column names to values into ordered column
// lists and placeholder slices suitable for a parameterized INSERT statement.
func mapToInsert(m map[string]any) (cols []string, vals []any, placeholders []string) {
	cols = make([]string, 0, len(m))
	vals = make([]any, 0, len(m))
	placeholders = make([]string, 0, len(m))

	for _, key := range orderedInsertColumns {
		if v, ok := m[key]; ok {
			cols = append(cols, key)
			vals = append(vals, v)
			placeholders = append(placeholders, "?")
		}
	}

	return cols, vals, placeholders
}

// orderedInsertColumns defines a deterministic ordering for map keys to ensure
// stable SQL generation. This avoids non-deterministic map iteration.
var orderedInsertColumns = []string{
	"id",
	"timestamp",
	"received_at",
	"source",
	"source_type",
	"host",
	"ip",
	"service",
	"application",
	"severity",
	"message",
	"event_type",
	"category",
	"action",
	"outcome",
	"user",
	"user_id",
	"process",
	"process_id",
	"parent_pid",
	"file_path",
	"destination_ip",
	"destination_port",
	"source_ip",
	"source_port",
	"raw",
	"raw_format",
	"trace_id",
	"span_id",
	"attributes",
}

// insertColumnOrder matches the columns in the same deterministic order.
var insertColumnOrder = orderedInsertColumns

func batchInsertTemplate() string {
	cols := strings.Join(insertColumnOrder, ", ")
	placeholders := strings.Repeat("?, ", len(insertColumnOrder))
	// Remove trailing comma+space
	placeholders = placeholders[:len(placeholders)-2]
	return fmt.Sprintf("INSERT INTO events (%s) VALUES (%s)", cols, placeholders)
}

// buildSearchQuery constructs the SQL query and arguments for the Search operation.
func buildSearchQuery(q Query) (string, []any, error) {
	var sb strings.Builder
	var args []any
	argIdx := 1

	sb.WriteString("SELECT events.id, events.timestamp, events.received_at, events.source, events.source_type, events.host, events.ip, events.service, " +
		"events.application, events.severity, events.message, events.event_type, events.category, events.action, events.outcome, " +
		"events.user, events.user_id, events.process, events.process_id, events.parent_pid, events.file_path, " +
		"events.destination_ip, events.destination_port, events.source_ip, events.source_port, " +
		"events.raw, events.raw_format, events.trace_id, events.span_id, events.attributes FROM events")

	hasWhere := false

	addFilter := func(col string, val any) {
		if !hasWhere {
			sb.WriteString(" WHERE ")
			hasWhere = true
		} else {
			sb.WriteString(" AND ")
		}
		sb.WriteString(col + " = ?")
		args = append(args, val)
		_ = argIdx
		argIdx++
	}

	// FTS5 text search
	if q.Text != "" {
		sb.WriteString(" INNER JOIN events_fts ON events.id = events_fts.rowid WHERE events_fts.events_fts MATCH ?")
		args = append(args, q.Text)
		hasWhere = true
	}

	// String filters — only include non-empty values
	if q.Source != "" {
		addFilter("source", q.Source)
	}
	if q.SourceType != "" {
		addFilter("source_type", q.SourceType)
	}
	if q.Host != "" {
		addFilter("host", q.Host)
	}
	if q.Service != "" {
		addFilter("service", q.Service)
	}
	if q.Severity != "" {
		addFilter("severity", q.Severity)
	}
	if q.EventType != "" {
		addFilter("event_type", q.EventType)
	}
	if q.Category != "" {
		addFilter("category", q.Category)
	}
	if q.Action != "" {
		addFilter("action", q.Action)
	}
	if q.Outcome != "" {
		addFilter("outcome", q.Outcome)
	}
	if q.User != "" {
		addFilter("user", q.User)
	}
	if q.SourceIP != "" {
		addFilter("source_ip", q.SourceIP)
	}
	if q.DestinationIP != "" {
		addFilter("destination_ip", q.DestinationIP)
	}

	// Time range filters
	if !q.Start.IsZero() {
		if !hasWhere {
			sb.WriteString(" WHERE ")
			hasWhere = true
		} else {
			sb.WriteString(" AND ")
		}
		sb.WriteString("timestamp >= ?")
		args = append(args, q.Start)
	}
	if !q.End.IsZero() {
		if !hasWhere {
			sb.WriteString(" WHERE ")
			hasWhere = true
		} else {
			sb.WriteString(" AND ")
		}
		sb.WriteString("timestamp <= ?")
		args = append(args, q.End)
	}

	// OR condition filters (from detection rules with OR queries)
	orFields := map[string]string{
		"__or_source__":     "source",
		"__or_event_type__": "event_type",
		"__or_host__":       "host",
		"__or_service__":    "service",
		"__or_severity__":   "severity",
		"__or_category__":   "category",
		"__or_action__":     "action",
		"__or_outcome__":    "outcome",
		"__or_user__":       "user",
	}
	for attrKey, sqlCol := range orFields {
		if orValues, ok := q.Attributes[attrKey]; ok {
			vals := strings.Split(orValues, ",")
			if len(vals) > 0 {
				placeholders := make([]string, len(vals))
				for i, v := range vals {
					placeholders[i] = "?"
					args = append(args, strings.TrimSpace(v))
				}
				if !hasWhere {
					sb.WriteString(" WHERE ")
					hasWhere = true
				} else {
					sb.WriteString(" AND ")
				}
				sb.WriteString(fmt.Sprintf("%s IN (%s)", sqlCol, strings.Join(placeholders, ", ")))
			}
		}
	}

	// Attribute key=value filters
	for k, v := range q.Attributes {
		if strings.HasPrefix(k, "__or_") {
			continue // skip OR markers, already handled above
		}
		key := strings.ToLower(k)
		addFilter(fmt.Sprintf("attr.%s", key), v)
	}

	// Ordering
	sb.WriteString(fmt.Sprintf(" ORDER BY %s %s", q.SortBy, q.SortOrder))

	// Pagination
	sb.WriteString(fmt.Sprintf(" LIMIT %d OFFSET %d", q.Limit, q.Offset))

	return sb.String(), args, nil
}

// rewriteToCount replaces the SELECT clause with SELECT COUNT(*) while
// preserving the WHERE clause but removing ORDER BY, LIMIT, and OFFSET.
func rewriteToCount(q string) string {
	// Find the first FROM keyword (case-insensitive).
	lower := strings.ToLower(q)
	idx := strings.Index(lower, " from ")
	if idx == -1 {
		// Fallback: just return a count query
		return "SELECT COUNT(*) FROM events"
	}

	// Take the part after FROM
	base := "SELECT COUNT(*) FROM " + q[idx+len(" from "):]

	// Remove ORDER BY and everything after it
	if oi := strings.Index(strings.ToLower(base), " order by "); oi > 0 {
		base = base[:oi]
	}
	// Remove LIMIT and everything after it
	if li := strings.Index(strings.ToLower(base), " limit "); li > 0 {
		base = base[:li]
	}
	// Remove OFFSET and everything after it
	if oi := strings.Index(strings.ToLower(base), " offset "); oi > 0 {
		base = base[:oi]
	}

	// Trim trailing whitespace and add semicolon
	return strings.TrimSpace(base)
}
