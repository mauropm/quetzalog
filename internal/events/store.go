package events

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"quetzalog/internal/correlation"
	"quetzalog/pkg/event"
)

// Store persists events to a SQLite database with FTS5 full-text search support.
type Store struct {
	db    *sql.DB
	graph *correlation.Graph
}

// ErrInvalidQuery indicates the caller supplied a query value that cannot be safely mapped to SQL.
var ErrInvalidQuery = errors.New("invalid event query")

// MaxSearchLimit hard-caps the SQL LIMIT emitted by buildSearchQuery so a
// forgotten caller-side clamp cannot produce an unbounded result set.
const MaxSearchLimit = 50000

// NewStore creates a new event store backed by the given database connection.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db, graph: correlation.NewGraph(db)}
}

// DB exposes the underlying database handle for read-only query planning used by
// the SPL engine (preview, distinct-value discovery). Callers must not mutate
// schema through this handle.
func (s *Store) DB() *sql.DB { return s.db }

// Create inserts a single event into the database.
func (s *Store) Create(ctx context.Context, ev *event.Event) error {
	if ev == nil {
		return fmt.Errorf("nil event provided")
	}
	normalizeEvent(ev)

	m := event.EventToMap(ev)

	// The column order is fixed, so the statement text is constant and can be
	// prepared once and reused by database/sql's statement cache.
	vals := make([]any, 0, len(insertColumnOrder))
	for _, col := range insertColumnOrder {
		if v, ok := m[col]; ok {
			vals = append(vals, v)
		} else {
			vals = append(vals, nil)
		}
	}

	_, err := s.db.ExecContext(ctx, insertSQL, vals...)
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}

	// Populate the entity correlation graph outside the insert so a graph
	// write failure surfaces instead of silently leaving the feature dead.
	if err := s.graph.AddEntityFromEvent(ctx, ev); err != nil {
		return fmt.Errorf("correlate event: %w", err)
	}

	return nil
}

// normalizeEvent fills timestamps that arrived unset so time-filtered
// queries (detections, timelines) see events instead of missing them.
func normalizeEvent(ev *event.Event) {
	if ev == nil {
		return
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	if ev.ReceivedAt.IsZero() {
		ev.ReceivedAt = ev.Timestamp
	}
}

// CreateBatch inserts multiple events in a single transaction.
func (s *Store) CreateBatch(ctx context.Context, events []*event.Event) error {
	if len(events) == 0 {
		return nil
	}
	for _, ev := range events {
		normalizeEvent(ev)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin batch transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, insertSQL)
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

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit batch transaction: %w", err)
	}

	// Populate the entity correlation graph after the commit: the graph
	// writes use separate statements, and doing them in the same transaction
	// would contend with the batch writer on another connection.
	for _, ev := range events {
		if ev == nil {
			continue
		}
		if err := s.graph.AddEntityFromEvent(ctx, ev); err != nil {
			return fmt.Errorf("correlate event %s: %w", ev.ID, err)
		}
	}

	return nil
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
		if errors.Is(err, sql.ErrNoRows) {
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
	if q.Limit > MaxSearchLimit {
		q.Limit = MaxSearchLimit
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
	countSQL, args, err := buildCountQuery(q)
	if err != nil {
		return 0, fmt.Errorf("build count query: %w", err)
	}

	var total int
	err = s.db.QueryRowContext(ctx, countSQL, args...).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("count events: %w", err)
	}

	return total, nil
}

// BucketCount is one point of an event timeline.
type BucketCount struct {
	Bucket   int64 `json:"bucket"`
	Total    int   `json:"total"`
	Critical int   `json:"critical"`
	High     int   `json:"high"`
	Medium   int   `json:"medium"`
	Low      int   `json:"low"`
}

// Timeline returns event counts bucketed by time over the window. Severities
// are folded onto the four-level SOC scale so the dashboard can chart the
// same buckets the analyst queue uses.
func (s *Store) Timeline(ctx context.Context, start, end time.Time, bucket time.Duration) ([]BucketCount, error) {
	if bucket < time.Minute {
		bucket = time.Minute
	}
	if bucket > 24*time.Hour {
		bucket = 24 * time.Hour
	}
	sec := int64(bucket.Seconds())

	// Timestamps are stored as UTC; binding non-UTC times breaks the
	// lexicographic comparison inside the WHERE clause.
	start, end = start.UTC(), end.UTC()

	rows, err := s.db.QueryContext(ctx,
		`SELECT (strftime('%s', timestamp) / ?) * ? AS bucket,
		        COUNT(*),
		        SUM(CASE WHEN severity IN ('critical','emergency','alert') THEN 1 ELSE 0 END),
		        SUM(CASE WHEN severity IN ('high','err','error') THEN 1 ELSE 0 END),
		        SUM(CASE WHEN severity IN ('medium','warning','warn','notice') THEN 1 ELSE 0 END),
		        SUM(CASE WHEN severity NOT IN ('critical','emergency','alert','high','err','error','medium','warning','warn','notice') THEN 1 ELSE 0 END)
		 FROM events
		 WHERE timestamp >= ? AND timestamp <= ?
		 GROUP BY bucket
		 ORDER BY bucket`, sec, sec, start, end)
	if err != nil {
		return nil, fmt.Errorf("query event timeline: %w", err)
	}
	defer rows.Close()

	var out []BucketCount
	for rows.Next() {
		var b BucketCount
		if err := rows.Scan(&b.Bucket, &b.Total, &b.Critical, &b.High, &b.Medium, &b.Low); err != nil {
			return nil, fmt.Errorf("scan timeline row: %w", err)
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate timeline: %w", err)
	}
	return out, nil
}

// Graph exposes the correlation graph used by the event pipeline.
func (s *Store) Graph() *correlation.Graph {
	return s.graph
}

// SourceCounts returns the number of events per source among the most recent
// limit rows. The sampling window matches the newest-first ordering used by
// Search, and the tally is done by the database rather than by materialising
// every sampled row into an Event.
func (s *Store) SourceCounts(ctx context.Context, limit int) (map[string]int, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > MaxSearchLimit {
		limit = MaxSearchLimit
	}

	const q = "SELECT source, COUNT(*) FROM (SELECT source FROM events ORDER BY timestamp DESC LIMIT ?) GROUP BY source"

	rows, err := s.db.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("group events by source: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var src string
		var n int
		if err := rows.Scan(&src, &n); err != nil {
			return nil, fmt.Errorf("scan source count: %w", err)
		}
		counts[src] += n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate source counts: %w", err)
	}
	return counts, nil
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
	var raw sql.NullString
	var attrs sql.NullString

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

	if raw.Valid {
		ev.Raw = []byte(raw.String)
	}
	if attrs.Valid && attrs.String != "" {
		var m map[string]any
		if err := json.Unmarshal([]byte(attrs.String), &m); err == nil {
			ev.Attributes = m
		} else {
			ev.Attributes = map[string]any{}
		}
	} else {
		ev.Attributes = map[string]any{}
	}

	return &ev, nil
}

// rowScanner is a common interface for sql.Row and sql.Rows Scan methods.
type rowScanner interface {
	Scan(dest ...any) error
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

// insertSQL is the fully rendered single-row INSERT statement for events. It
// is derived once from insertColumnOrder instead of being rebuilt on every
// write so hot insert paths never touch fmt or strings.Join.
var insertSQL = buildInsertSQL()

func buildInsertSQL() string {
	cols := strings.Join(insertColumnOrder, ", ")
	placeholders := strings.Repeat("?, ", len(insertColumnOrder))
	// Remove trailing comma+space
	placeholders = placeholders[:len(placeholders)-2]
	return fmt.Sprintf("INSERT INTO events (%s) VALUES (%s)", cols, placeholders)
}

var sortColumns = map[string]string{
	"id":               "id",
	"timestamp":        "timestamp",
	"received_at":      "received_at",
	"source":           "source",
	"source_type":      "source_type",
	"host":             "host",
	"ip":               "ip",
	"service":          "service",
	"application":      "application",
	"severity":         "severity",
	"message":          "message",
	"event_type":       "event_type",
	"category":         "category",
	"action":           "action",
	"outcome":          "outcome",
	"user":             "user",
	"user_id":          "user_id",
	"process":          "process",
	"process_id":       "process_id",
	"parent_pid":       "parent_pid",
	"file_path":        "file_path",
	"destination_ip":   "destination_ip",
	"destination_port": "destination_port",
	"source_ip":        "source_ip",
	"source_port":      "source_port",
	"raw_format":       "raw_format",
	"trace_id":         "trace_id",
	"span_id":          "span_id",
}

var validAttrKey = regexp.MustCompile(`^[a-z0-9_]+$`)
var ftsToken = regexp.MustCompile(`[[:alnum:]_]+`)

func sanitizeFTSMatch(q string) string {
	tokens := ftsToken.FindAllString(q, -1)
	if len(tokens) == 0 {
		return `""`
	}
	// Tokens are restricted to the alnum/underscore class above, so wrapping
	// them in FTS5 quotes needs no escaping and can be written directly.
	var sb strings.Builder
	sb.Grow(len(q) + 4*len(tokens))
	for i, tok := range tokens {
		if i > 0 {
			sb.WriteString(" AND ")
		}
		sb.WriteByte('"')
		sb.WriteString(tok)
		sb.WriteByte('"')
	}
	return sb.String()
}

// buildSearchQuery constructs the SQL query and arguments for the Search operation.
func buildSearchQuery(q Query) (string, []any, error) {
	return buildEventQuery(q, false)
}

// buildCountQuery builds the COUNT(*) variant of the same predicate. It shares
// all WHERE construction with buildSearchQuery rather than rebuilding the wide
// SELECT list only to discard it again afterwards.
func buildCountQuery(q Query) (string, []any, error) {
	return buildEventQuery(q, true)
}

func buildEventQuery(q Query, countOnly bool) (string, []any, error) {
	if q.Limit <= 0 {
		q.Limit = 100
	}
	if q.Limit > MaxSearchLimit {
		q.Limit = MaxSearchLimit
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

	var sb strings.Builder
	var args []any
	argIdx := 1

	if countOnly {
		sb.WriteString("SELECT COUNT(*) FROM events")
	} else {
		sb.WriteString("SELECT events.id, events.timestamp, events.received_at, events.source, events.source_type, events.host, events.ip, events.service, " +
			"events.application, events.severity, events.message, events.event_type, events.category, events.action, events.outcome, " +
			"events.user, events.user_id, events.process, events.process_id, events.parent_pid, events.file_path, " +
			"events.destination_ip, events.destination_port, events.source_ip, events.source_port, " +
			"events.raw, events.raw_format, events.trace_id, events.span_id, events.attributes FROM events")
	}

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
		sb.WriteString(" WHERE events.rowid IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)")
		args = append(args, sanitizeFTSMatch(q.Text))
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
		args = append(args, q.Start.UTC())
	}
	if !q.End.IsZero() {
		if !hasWhere {
			sb.WriteString(" WHERE ")
			hasWhere = true
		} else {
			sb.WriteString(" AND ")
		}
		sb.WriteString("timestamp <= ?")
		args = append(args, q.End.UTC())
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
		if !validAttrKey.MatchString(key) {
			return "", nil, fmt.Errorf("%w: invalid attribute key %q", ErrInvalidQuery, k)
		}
		if !hasWhere {
			sb.WriteString(" WHERE ")
			hasWhere = true
		} else {
			sb.WriteString(" AND ")
		}
		sb.WriteString(fmt.Sprintf(`json_extract(attributes, '$."%s"') = ?`, key))
		args = append(args, v)
	}

	// Ordering
	col, ok := sortColumns[strings.ToLower(q.SortBy)]
	if !ok {
		return "", nil, fmt.Errorf("%w: invalid sort column %q", ErrInvalidQuery, q.SortBy)
	}
	if !countOnly {
		sb.WriteString(fmt.Sprintf(" ORDER BY %s %s", col, q.SortOrder))

		// Pagination
		sb.WriteString(fmt.Sprintf(" LIMIT %d OFFSET %d", q.Limit, q.Offset))
	}

	return sb.String(), args, nil
}
