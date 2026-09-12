package detections

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"quetzalog/internal/events"
	"quetzalog/internal/findings"
	"quetzalog/internal/risk"
	"quetzalog/pkg/event"
)

// DetectionRule represents a detection rule that evaluates events and
// generates findings. It reuses the platform query language for its
// definition: `Query` is an SPL-like filter, optionally with a threshold.
type DetectionRule struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Description      string     `json:"description"`
	Query            string     `json:"query"`
	Severity         string     `json:"severity"`
	Enabled          bool       `json:"enabled"`
	Threshold        *Threshold `json:"threshold,omitempty"`
	GroupBy          []string   `json:"group_by,omitempty"`
	RiskScore        float64    `json:"risk_score"`
	Tags             []string   `json:"tags"`
	MITRETactic      string     `json:"mitre_tactic,omitempty"`
	MITRETechnique   string     `json:"mitre_technique,omitempty"`
	ScheduleSeconds  int        `json:"schedule_seconds"`
	CreatedBy        string     `json:"created_by,omitempty"`
	DataSources      []string   `json:"data_sources"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// Threshold defines the counting window for a detection rule.
type Threshold struct {
	Count  int    `json:"count"`
	Window string `json:"window"`
}

// ExecutionResult holds the output of a detection rule execution.
type ExecutionResult struct {
	Matched  int           `json:"matched"`
	Total    int           `json:"total"`
	Alerts   []string      `json:"alerts"`
	Duration time.Duration `json:"duration"`
}

// FindingRunResult holds the output of a detection run that creates findings.
type FindingRunResult struct {
	Matched  int           `json:"matched"`
	Total    int           `json:"total"`
	Findings []string      `json:"findings"`
	Created  int           `json:"created"`
	Duration time.Duration `json:"duration"`
}

// Store persists and queries detection rules.
type Store struct {
	db *sql.DB
}

// NewStore creates a new detection store backed by the given database.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// Create inserts a new detection rule.
func (s *Store) Create(ctx context.Context, rule *DetectionRule) error {
	if rule == nil {
		return fmt.Errorf("nil detection rule provided")
	}

	if rule.ID == "" {
		rule.ID = uuid.New().String()
	}
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()

	thresholdWindow := sql.NullString{}
	thresholdCount := sql.NullInt64{}
	if rule.Threshold != nil {
		thresholdWindow = sql.NullString{String: rule.Threshold.Window, Valid: true}
		thresholdCount = sql.NullInt64{Int64: int64(rule.Threshold.Count), Valid: true}
	} else {
		thresholdWindow = sql.NullString{String: "", Valid: true}
		thresholdCount = sql.NullInt64{Int64: 0, Valid: true}
	}

	groupBy := ""
	if len(rule.GroupBy) > 0 {
		groupBy = strings.Join(rule.GroupBy, ",")
	}

	query := `INSERT INTO detection_rules (id, name, description, query, severity, enabled, threshold_count, threshold_window, group_by,
	          risk_score, tags, mitre_tactic, mitre_technique, schedule_seconds, created_by, data_sources, created_at, updated_at)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query,
		rule.ID,
		rule.Name,
		rule.Description,
		rule.Query,
		rule.Severity,
		rule.Enabled,
		thresholdCount,
		thresholdWindow,
		groupBy,
		rule.RiskScore,
		encodeStringList(rule.Tags),
		rule.MITRETactic,
		rule.MITRETechnique,
		rule.ScheduleSeconds,
		rule.CreatedBy,
		encodeStringList(rule.DataSources),
		rule.CreatedAt,
		rule.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("create detection rule: %w", err)
	}

	return nil
}

// GetByID retrieves a detection rule by its ID.
func (s *Store) GetByID(ctx context.Context, id string) (*DetectionRule, error) {
	if id == "" {
		return nil, fmt.Errorf("empty detection rule ID")
	}

	row := s.db.QueryRowContext(ctx, ruleSelectSQL+` WHERE id = ?`, id)
	rule, err := scanDetectionRule(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("detection rule %s not found", id)
		}
		return nil, fmt.Errorf("query detection rule %s: %w", id, err)
	}

	return rule, nil
}

const ruleSelectSQL = `SELECT id, name, description, query, severity, enabled, threshold_count, threshold_window, group_by,
       risk_score, tags, mitre_tactic, mitre_technique, schedule_seconds, created_by, data_sources,
       created_at, updated_at FROM detection_rules`

// rowScanner is the common sql.Row/sql.Rows Scan interface.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanDetectionRule(row rowScanner) (*DetectionRule, error) {
	rule := &DetectionRule{}
	var thresholdCount sql.NullInt64
	var thresholdWindow sql.NullString
	var groupBy, tags, tactic, technique, createdBy, dataSources sql.NullString
	var riskScore sql.NullFloat64
	var scheduleSeconds sql.NullInt64

	err := row.Scan(
		&rule.ID,
		&rule.Name,
		&rule.Description,
		&rule.Query,
		&rule.Severity,
		&rule.Enabled,
		&thresholdCount,
		&thresholdWindow,
		&groupBy,
		&riskScore,
		&tags,
		&tactic,
		&technique,
		&scheduleSeconds,
		&createdBy,
		&dataSources,
		&rule.CreatedAt,
		&rule.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	rule.RiskScore = riskScore.Float64
	rule.Tags = decodeStringList(tags.String)
	rule.MITRETactic = tactic.String
	rule.MITRETechnique = technique.String
	rule.ScheduleSeconds = int(scheduleSeconds.Int64)
	rule.CreatedBy = createdBy.String
	rule.DataSources = decodeStringList(dataSources.String)
	if rule.Tags == nil {
		rule.Tags = []string{}
	}
	if rule.DataSources == nil {
		rule.DataSources = []string{}
	}
	if thresholdCount.Valid && thresholdCount.Int64 > 0 {
		rule.Threshold = &Threshold{
			Count:  int(thresholdCount.Int64),
			Window: thresholdWindow.String,
		}
	}
	if groupBy.String != "" {
		rule.GroupBy = strings.Split(groupBy.String, ",")
	}

	return rule, nil
}

// List returns all detection rules.
func (s *Store) List(ctx context.Context) ([]*DetectionRule, error) {
	rows, err := s.db.QueryContext(ctx, ruleSelectSQL+` ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("list detection rules: %w", err)
	}
	defer rows.Close()

	var rules []*DetectionRule
	for rows.Next() {
		rule, err := scanDetectionRule(rows)
		if err != nil {
			return nil, fmt.Errorf("scan detection rule row: %w", err)
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate detection rules: %w", err)
	}

	return rules, nil
}

// Update updates an existing detection rule.
func (s *Store) Update(ctx context.Context, rule *DetectionRule) error {
	if rule == nil {
		return fmt.Errorf("nil detection rule provided")
	}
	if rule.ID == "" {
		return fmt.Errorf("empty detection rule ID")
	}
	rule.UpdatedAt = time.Now()

	thresholdWindow := sql.NullString{String: "300s", Valid: true}
	thresholdCount := sql.NullInt64{Int64: 1, Valid: true}
	if rule.Threshold != nil {
		thresholdWindow = sql.NullString{String: rule.Threshold.Window, Valid: true}
		thresholdCount = sql.NullInt64{Int64: int64(rule.Threshold.Count), Valid: true}
	}

	groupBy := ""
	if len(rule.GroupBy) > 0 {
		groupBy = strings.Join(rule.GroupBy, ",")
	}

	query := `UPDATE detection_rules SET name = ?, description = ?, query = ?, severity = ?, enabled = ?,
	          threshold_count = ?, threshold_window = ?, group_by = ?, updated_at = ? WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query,
		rule.Name,
		rule.Description,
		rule.Query,
		rule.Severity,
		rule.Enabled,
		thresholdCount,
		thresholdWindow,
		groupBy,
		rule.UpdatedAt,
		rule.ID,
	)
	if err != nil {
		return fmt.Errorf("update detection rule: %w", err)
	}

	return nil
}

// Delete removes a detection rule by its ID.
func (s *Store) Delete(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("empty detection rule ID")
	}

	query := `DELETE FROM detection_rules WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete detection rule: %w", err)
	}

	return nil
}

// Enable marks a detection rule as enabled.
func (s *Store) Enable(ctx context.Context, id string) error {
	return s.setEnabled(ctx, id, true)
}

// Disable marks a detection rule as disabled.
func (s *Store) Disable(ctx context.Context, id string) error {
	return s.setEnabled(ctx, id, false)
}

func (s *Store) setEnabled(ctx context.Context, id string, enabled bool) error {
	if id == "" {
		return fmt.Errorf("empty detection rule ID")
	}

	query := `UPDATE detection_rules SET enabled = ?, updated_at = ? WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, enabled, time.Now(), id)
	if err != nil {
		return fmt.Errorf("toggle detection rule enabled: %w", err)
	}

	return nil
}

func encodeStringList(list []string) string {
	if len(list) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(list)
	return string(b)
}

func decodeStringList(s string) []string {
	if s == "" || s == "null" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}

func parseDetectionWindow(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("empty detection window")
	}
	if secs, err := strconv.Atoi(value); err == nil {
		if secs < 0 {
			return 0, fmt.Errorf("negative detection window")
		}
		return time.Duration(secs) * time.Second, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid detection window %q: %w", value, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("negative detection window")
	}
	return d, nil
}

// ExecuteNow runs a detection rule immediately against the events store.
func (s *Store) ExecuteNow(ctx context.Context, rule *DetectionRule, evStore *events.Store) (*ExecutionResult, error) {
	if rule == nil {
		return nil, fmt.Errorf("nil detection rule")
	}
	if evStore == nil {
		return nil, fmt.Errorf("nil event store")
	}

	start := time.Now()

	// Parse the detection rule query to build an events.Query
	evQuery, err := parseDetectionQuery(rule)
	if err != nil {
		return nil, fmt.Errorf("parse detection query: %w", err)
	}

	total, err := evStore.Count(ctx, *evQuery)
	if err != nil {
		return nil, fmt.Errorf("count events: %w", err)
	}

	result := ExecutionResult{
		Total:    total,
		Matched:  total,
		Duration: time.Since(start),
	}

	if rule.Threshold == nil || rule.Threshold.Count <= 0 {
		return &result, nil
	}

	if len(rule.GroupBy) > 0 {
		evQuery.Limit = total
		if evQuery.Limit > events.MaxSearchLimit {
			evQuery.Limit = events.MaxSearchLimit
		}
		evts, err := evStore.Search(ctx, *evQuery)
		if err != nil {
			return nil, fmt.Errorf("search events: %w", err)
		}
		result.Matched = countGroupedThresholdEvents(evts, rule)
	} else if total < rule.Threshold.Count {
		result.Matched = 0
	}

	return &result, nil
}

// RunWithFindings executes the rule and materializes one finding per
// threshold-exceeding group. Findings are deduplicated by detection + group,
// so repeated runs refresh instead of flooding the queue. Risk contributions
// are recorded for the entities involved so entity risk stays transparent.
func (s *Store) RunWithFindings(ctx context.Context, rule *DetectionRule, evStore *events.Store, findingStore *findings.Store, riskStore *risk.EntityRiskStore) (*FindingRunResult, error) {
	if rule == nil {
		return nil, fmt.Errorf("nil detection rule")
	}
	if evStore == nil {
		return nil, fmt.Errorf("nil event store")
	}
	if findingStore == nil {
		return nil, fmt.Errorf("nil findings store")
	}

	start := time.Now()

	evQuery, err := parseDetectionQuery(rule)
	if err != nil {
		return nil, fmt.Errorf("parse detection query: %w", err)
	}

	total, err := evStore.Count(ctx, *evQuery)
	if err != nil {
		return nil, fmt.Errorf("count events: %w", err)
	}

	result := &FindingRunResult{Total: total}

	threshold := rule.Threshold
	hasThreshold := threshold != nil && threshold.Count > 0

	if hasThreshold && total == 0 {
		result.Duration = time.Since(start)
		return result, nil
	}

	limit := total
	if limit <= 0 {
		limit = 200
	}
	if limit > events.MaxSearchLimit {
		limit = events.MaxSearchLimit
	}
	evQuery.Limit = limit
	evts, err := evStore.Search(ctx, *evQuery)
	if err != nil {
		return nil, fmt.Errorf("search events: %w", err)
	}

	dataSource := ""
	if len(rule.DataSources) > 0 {
		dataSource = rule.DataSources[0]
	}

	if len(rule.GroupBy) > 0 {
		groups := make(map[string][]*event.Event)
		for _, ev := range evts {
			groups[groupKey(ev, rule.GroupBy)] = append(groups[groupKey(ev, rule.GroupBy)], ev)
		}
		for key, groupEvents := range groups {
			if hasThreshold && len(groupEvents) < threshold.Count {
				continue
			}
			created, isNew, err := s.upsertFinding(ctx, rule, key, groupEvents, findingStore, riskStore, dataSource)
			if err != nil {
				return nil, err
			}
			result.Matched += len(groupEvents)
			result.Findings = append(result.Findings, created.ID)
			if isNew {
				result.Created++
			}
		}
	} else {
		if hasThreshold && total < threshold.Count {
			result.Duration = time.Since(start)
			return result, nil
		}
		sample := evts
		if len(sample) > 200 {
			sample = sample[:200]
		}
		created, isNew, err := s.upsertFinding(ctx, rule, "global", sample, findingStore, riskStore, dataSource)
		if err != nil {
			return nil, err
		}
		result.Matched = total
		result.Findings = append(result.Findings, created.ID)
		if isNew {
			result.Created++
		}
	}

	result.Duration = time.Since(start)
	return result, nil
}

// upsertFinding creates or refreshes one finding for a detection group and
// records the risk contributions of its entities.
func (s *Store) upsertFinding(ctx context.Context, rule *DetectionRule, groupKey string, groupEvents []*event.Event, findingStore *findings.Store, riskStore *risk.EntityRiskStore, dataSource string) (*findings.Finding, bool, error) {
	f, isNew, err := findingStore.CreateOrUpdateFromDetection(ctx, findings.FromDetectionArgs{
		RuleID:         rule.ID,
		RuleName:       rule.Name,
		GroupKey:       groupKey,
		Title:          rule.Name,
		Description:    rule.Description,
		Severity:       rule.Severity,
		RiskScore:      rule.RiskScore,
		DataSource:     dataSource,
		MITRETactic:    rule.MITRETactic,
		MITRETechnique: rule.MITRETechnique,
		Tags:           rule.Tags,
		Matched:        len(groupEvents),
		Events:         groupEvents,
	})
	if err != nil {
		return nil, false, fmt.Errorf("upsert finding: %w", err)
	}

	if isNew && riskStore != nil && f.RiskScore > 0 {
		for _, e := range f.Entities {
			parts := strings.SplitN(e, ":", 2)
			if len(parts) != 2 || parts[1] == "" {
				continue
			}
			et, ev := parts[0], parts[1]
			points := f.RiskScore
			if et == "process" {
				points = f.RiskScore / 2
			}
			_ = riskStore.Record(ctx, risk.Contribution{
				EntityType:  et,
				EntityValue: ev,
				SourceType:  "finding",
				SourceID:    f.ID,
				Description: fmt.Sprintf("%s (%s)", f.Title, f.Severity),
				Points:      points,
			})
		}
	}

	return f, isNew, nil
}

func countGroupedThresholdEvents(events []*event.Event, rule *DetectionRule) int {
	if rule.Threshold == nil || rule.Threshold.Count <= 0 {
		return len(events)
	}
	groups := make(map[string]int)
	for _, ev := range events {
		key := groupKey(ev, rule.GroupBy)
		groups[key]++
	}
	matched := 0
	for _, n := range groups {
		if n >= rule.Threshold.Count {
			matched += n
		}
	}
	return matched
}

func groupKey(ev *event.Event, fields []string) string {
	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		switch strings.ToLower(f) {
		case "source_ip":
			parts = append(parts, ev.SourceIP)
		case "destination_ip":
			parts = append(parts, ev.DestinationIP)
		case "host":
			parts = append(parts, ev.Host)
		case "user":
			parts = append(parts, ev.User)
		case "source":
			parts = append(parts, ev.Source)
		case "service":
			parts = append(parts, ev.Service)
		case "severity":
			parts = append(parts, ev.Severity)
		case "event_type":
			parts = append(parts, ev.EventType)
		default:
			v := ev.Attributes[strings.ToLower(f)]
			parts = append(parts, fmt.Sprintf("%v", v))
		}
	}
	return strings.Join(parts, "|")
}

// parseDetectionQuery converts a detection rule's query string into an events.Query.
func parseDetectionQuery(rule *DetectionRule) (*events.Query, error) {
	q := events.NewQuery()

	query := rule.Query
	if query == "" {
		return nil, fmt.Errorf("empty query")
	}

	// Simple parser: split by pipe for SPL-like queries
	parts := strings.Split(query, "|")
	baseQuery := strings.TrimSpace(parts[0])

	// Parse the base query for fields like source=..., event_type=...
	q = parseBaseQuery(baseQuery)

	// If there's a threshold window, apply time constraints
	if rule.Threshold != nil && rule.Threshold.Window != "" {
		window, err := parseDetectionWindow(rule.Threshold.Window)
		if err != nil {
			return nil, fmt.Errorf("invalid threshold window: %w", err)
		}
		now := time.Now().UTC()
		q.End = now
		q.Start = now.Add(-window)
	}

	return &q, nil
}

// parseBaseQuery parses a base SPL-like query string and returns an events.Query.
// Handles OR conditions by splitting on " OR " and collecting matching values.
func parseBaseQuery(q string) events.Query {
	filter := events.NewQuery()

	// Split on OR first
	orParts := strings.Split(q, " OR ")
	// If no OR, process as a single part
	if len(orParts) == 1 {
		return parseSingleQuery(q, filter)
	}

	// Process each OR part and collect field mappings for OR matching
	fieldValues := make(map[string][]string)
	for _, orPart := range orParts {
		parsed := parseSingleQuery(orPart, filter)
		// Collect text for OR matching
		if parsed.Text != "" {
			for _, t := range strings.Fields(parsed.Text) {
				fieldValues["__text__"] = append(fieldValues["__text__"], t)
			}
		}
		if parsed.Source != "" {
			fieldValues["source"] = append(fieldValues["source"], parsed.Source)
		}
		if parsed.EventType != "" {
			fieldValues["event_type"] = append(fieldValues["event_type"], parsed.EventType)
		}
		if parsed.Host != "" {
			fieldValues["host"] = append(fieldValues["host"], parsed.Host)
		}
		if parsed.Service != "" {
			fieldValues["service"] = append(fieldValues["service"], parsed.Service)
		}
		if parsed.Severity != "" {
			fieldValues["severity"] = append(fieldValues["severity"], parsed.Severity)
		}
		if parsed.Category != "" {
			fieldValues["category"] = append(fieldValues["category"], parsed.Category)
		}
		if parsed.Action != "" {
			fieldValues["action"] = append(fieldValues["action"], parsed.Action)
		}
		if parsed.Outcome != "" {
			fieldValues["outcome"] = append(fieldValues["outcome"], parsed.Outcome)
		}
		if parsed.User != "" {
			fieldValues["user"] = append(fieldValues["user"], parsed.User)
		}
		for k, v := range parsed.Attributes {
			fieldValues[k] = append(fieldValues[k], v)
		}
	}

	// For fields with multiple OR values, don't set the field filter directly.
	// Instead store all values in attributes for the event store to handle with IN clause.
	filter.Attributes = make(map[string]string)
	for field, values := range fieldValues {
		if len(values) > 1 {
			// Store all values joined with comma for the store to use in IN clause
			attrKey := "__or_" + field + "__"
			filter.Attributes[attrKey] = strings.Join(values, ",")
		}
	}

	return filter
}

// parseSingleQuery parses a single query expression without OR handling.
func parseSingleQuery(q string, filter events.Query) events.Query {
	if filter.Attributes == nil {
		filter.Attributes = make(map[string]string)
	}
	parts := strings.Fields(q)
	for _, part := range parts {
		if strings.EqualFold(part, "AND") || strings.EqualFold(part, "OR") {
			continue
		}
		if idx := strings.Index(part, "="); idx > 0 {
			key := strings.ToLower(strings.TrimSpace(part[:idx]))
			value := strings.TrimSpace(part[idx+1:])

			switch key {
			case "source":
				filter.Source = value
			case "event_type", "eventtype", "sourcetype":
				filter.EventType = value
			case "host":
				filter.Host = value
			case "service":
				filter.Service = value
			case "severity", "sev":
				filter.Severity = value
			case "category":
				filter.Category = value
			case "action":
				filter.Action = value
			case "outcome":
				filter.Outcome = value
			case "user":
				filter.User = value
			default:
				if filter.Attributes == nil {
					filter.Attributes = make(map[string]string)
				}
				filter.Attributes[key] = value
			}
		} else {
			// Free text search via FTS5
			if filter.Text == "" {
				filter.Text = part
			} else {
				filter.Text += " " + part
			}
		}
	}

	return filter
}

// filterByThresholdEvents applies the threshold count and window to the events.
func filterByThresholdEvents(events []*event.Event, rule *DetectionRule) []*event.Event {
	if rule.Threshold == nil || rule.Threshold.Count <= 0 {
		return events
	}

	// For now, return events that meet the threshold count
	if len(events) >= rule.Threshold.Count {
		return events
	}

	return nil
}
