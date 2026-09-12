// Package findings implements the SOC analyst queue: security findings
// aggregated from detection runs, with rich server-side filtering, notes,
// ownership and lifecycle. Findings are the unit of triage; investigations
// are where the security story gets built.
package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"quetzalog/pkg/event"
)

// Finding is a triage-level security story produced by a detection run.
type Finding struct {
	ID             string    `json:"id"`
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	Severity       string    `json:"severity"`
	Status         string    `json:"status"`
	RiskScore      float64   `json:"risk_score"`
	DetectionID    string    `json:"detection_id,omitempty"`
	DetectionName  string    `json:"detection_name,omitempty"`
	DedupKey       string    `json:"-"`
	User           string    `json:"user,omitempty"`
	Host           string    `json:"host,omitempty"`
	SourceIP       string    `json:"source_ip,omitempty"`
	DestinationIP  string    `json:"destination_ip,omitempty"`
	DataSource     string    `json:"data_source,omitempty"`
	MITRETactic    string    `json:"mitre_tactic,omitempty"`
	MITRETechnique string    `json:"mitre_technique,omitempty"`
	Owner          string    `json:"owner,omitempty"`
	Tags           []string  `json:"tags"`
	AlertIDs       []string  `json:"alert_ids"`
	EventIDs       []string  `json:"event_ids"`
	Entities       []string  `json:"entities"`
	MatchCount     int       `json:"match_count"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Notes          []Note    `json:"notes"`
}

// Note is an analyst note attached to a finding.
type Note struct {
	ID        string    `json:"id"`
	FindingID string    `json:"finding_id"`
	Author    string    `json:"author"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

// Store persists and queries findings.
type Store struct {
	db *sql.DB
}

// NewStore creates a finding store on the given database.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// Statuses is the finding lifecycle.
var Statuses = []string{"new", "in_progress", "investigating", "contained", "resolved", "false_positive"}

// ValidStatus reports whether s is part of the finding lifecycle.
func ValidStatus(s string) bool {
	for _, v := range Statuses {
		if v == s {
			return true
		}
	}
	return false
}

// Severity normalizes a raw severity (syslog-style or SOC-level) to the
// four-level SOC scale used by the queue.
func Severity(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical", "emergency", "alert":
		return "critical"
	case "high", "err", "error":
		return "high"
	case "medium", "warning", "warn", "notice":
		return "medium"
	case "low", "info", "debug", "":
		return "low"
	}
	return "medium"
}

// SeverityPoints gives the default risk points for a normalized severity.
func SeverityPoints(sev string) float64 {
	switch Severity(sev) {
	case "critical":
		return 50
	case "high":
		return 35
	case "medium":
		return 20
	default:
		return 10
	}
}

// Filter carries the analyst queue filter parameters.
type Filter struct {
	Severity    string
	Status      string
	Owner       string
	DetectionID string
	User        string
	Host        string
	SourceIP    string
	DestIP      string
	RiskMin     float64
	HasRisk     bool
	Tactic      string
	Technique   string
	Source      string
	Tag         string
	Text        string
	Start       time.Time
	End         time.Time
	SortBy      string
	SortOrder   string
	Limit       int
	Offset      int
}

const maxFindingLimit = 500

// Create inserts a new finding.
func (s *Store) Create(ctx context.Context, f *Finding) error {
	if f == nil {
		return fmt.Errorf("nil finding")
	}
	if f.ID == "" {
		f.ID = uuid.New().String()
	}
	if f.Severity == "" {
		f.Severity = "medium"
	}
	if f.Status == "" {
		f.Status = "new"
	}
	if f.FirstSeen.IsZero() {
		f.FirstSeen = time.Now().UTC()
	}
	if f.LastSeen.IsZero() {
		f.LastSeen = f.FirstSeen
	}
	now := time.Now().UTC()
	f.CreatedAt = now
	f.UpdatedAt = now

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO findings (id, title, description, severity, status, risk_score, detection_id, detection_name,
		  dedup_key, user, host, source_ip, destination_ip, data_source, mitre_tactic, mitre_technique,
		  owner, tags, alert_ids, event_ids, entities, match_count, first_seen, last_seen, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.Title, nullStr(f.Description), f.Severity, f.Status, f.RiskScore,
		nullStr(f.DetectionID), nullStr(f.DetectionName), nullStr(f.DedupKey),
		nullStr(f.User), nullStr(f.Host), nullStr(f.SourceIP), nullStr(f.DestinationIP),
		nullStr(f.DataSource), nullStr(f.MITRETactic), nullStr(f.MITRETechnique), nullStr(f.Owner),
		encodeStrings(f.Tags), encodeStrings(f.AlertIDs), encodeStrings(f.EventIDs), encodeStrings(f.Entities),
		f.MatchCount, f.FirstSeen, f.LastSeen, f.CreatedAt, f.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("create finding: %w", err)
	}
	return nil
}

// CreateOrUpdateFromDetection upserts the finding produced by one detection
// group. The dedup key is detection ID + group key, so repeated runs of the
// same detection refresh the finding instead of flooding the queue.
func (s *Store) CreateOrUpdateFromDetection(ctx context.Context, args FromDetectionArgs) (*Finding, bool, error) {
	if args.RuleID == "" || args.GroupKey == "" {
		return nil, false, fmt.Errorf("rule and group key required")
	}

	dedupKey := args.RuleID + "|" + args.GroupKey

	existing, err := s.ByDedupKey(ctx, dedupKey)
	if err != nil {
		return nil, false, err
	}

	evtIDs := make([]string, 0, len(args.Events))
	seen := map[string]bool{}
	ents := map[string]bool{}
	addEntity := func(t, v string) {
		if v == "" {
			return
		}
		ents[t+":"+v] = true
	}

	for _, ev := range args.Events {
		if ev == nil || ev.ID == "" {
			continue
		}
		if !seen[ev.ID] {
			seen[ev.ID] = true
			evtIDs = append(evtIDs, ev.ID)
		}
		addEntity("user", ev.User)
		addEntity("host", ev.Host)
		addEntity("ip", ev.SourceIP)
		addEntity("ip", ev.DestinationIP)
		addEntity("process", ev.Process)
	}

	entityList := make([]string, 0, len(ents))
	for k := range ents {
		entityList = append(entityList, k)
	}

	primaryUser, primaryHost, primarySrcIP, primaryDstIP := primaryEntities(args.Events)

	if existing != nil {
		existing.LastSeen = time.Now().UTC()
		existing.MatchCount += args.Matched
		existing.EventIDs = mergeStrings(existing.EventIDs, evtIDs, 200)
		existing.Entities = mergeStrings(existing.Entities, entityList, 50)
		if existing.User == "" {
			existing.User = primaryUser
		}
		if existing.Host == "" {
			existing.Host = primaryHost
		}
		if existing.SourceIP == "" {
			existing.SourceIP = primarySrcIP
		}
		if existing.DestinationIP == "" {
			existing.DestinationIP = primaryDstIP
		}
		if args.RiskScore > existing.RiskScore {
			existing.RiskScore = args.RiskScore
		}
		if err := s.Update(ctx, existing); err != nil {
			return nil, false, err
		}
		return existing, false, nil
	}

	title := args.Title
	if title == "" {
		title = args.RuleName
	}
	if title == "" {
		title = "Detection"
	}
	if args.GroupKey != "global" {
		title = fmt.Sprintf("%s — %s", title, args.GroupKey)
	}

	f := &Finding{
		Title:          title,
		Description:    args.Description,
		Severity:       Severity(args.Severity),
		Status:         "new",
		RiskScore:      args.RiskScore,
		DetectionID:    args.RuleID,
		DetectionName:  args.RuleName,
		DedupKey:       dedupKey,
		User:           primaryUser,
		Host:           primaryHost,
		SourceIP:       primarySrcIP,
		DestinationIP:  primaryDstIP,
		DataSource:     args.DataSource,
		MITRETactic:    args.MITRETactic,
		MITRETechnique: args.MITRETechnique,
		Tags:           args.Tags,
		AlertIDs:       []string{},
		EventIDs:       evtIDs,
		Entities:       entityList,
		MatchCount:     args.Matched,
		FirstSeen:      time.Now().UTC(),
		LastSeen:       time.Now().UTC(),
	}

	if args.RiskScore == 0 {
		f.RiskScore = SeverityPoints(f.Severity)
	}

	if err := s.Create(ctx, f); err != nil {
		return nil, false, err
	}
	return f, true, nil
}

// FromDetectionArgs carries everything needed to upsert a detection finding.
type FromDetectionArgs struct {
	RuleID         string
	RuleName       string
	GroupKey       string
	Title          string
	Description    string
	Severity       string
	RiskScore      float64
	DataSource     string
	MITRETactic    string
	MITRETechnique string
	Tags           []string
	Matched        int
	Events         []*event.Event
}

// ByDedupKey finds the finding for a detection group, or nil.
func (s *Store) ByDedupKey(ctx context.Context, key string) (*Finding, error) {
	if key == "" {
		return nil, nil
	}
	row := s.db.QueryRowContext(ctx, findingSelectSQL+` WHERE dedup_key = ?`, key)
	f, err := scanFinding(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return f, nil
}

const findingSelectSQL = `SELECT id, title, description, severity, status, risk_score, detection_id, detection_name,
       dedup_key, user, host, source_ip, destination_ip, data_source, mitre_tactic, mitre_technique,
       owner, tags, alert_ids, event_ids, entities, match_count, first_seen, last_seen, created_at, updated_at
       FROM findings`

func scanFinding(row rowScanner) (*Finding, error) {
	f := &Finding{}
	var desc, detID, detName, dedup, user, host, srcIP, dstIP, ds, tactic, technique, owner sql.NullString
	var tags, alertIDs, eventIDs, entities sql.NullString
	err := row.Scan(
		&f.ID, &f.Title, &desc, &f.Severity, &f.Status, &f.RiskScore, &detID, &detName, &dedup,
		&user, &host, &srcIP, &dstIP, &ds, &tactic, &technique, &owner,
		&tags, &alertIDs, &eventIDs, &entities, &f.MatchCount, &f.FirstSeen, &f.LastSeen, &f.CreatedAt, &f.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	applyFindingNulls(f, desc, detID, detName, dedup, user, host, srcIP, dstIP, ds, tactic, technique, owner, tags, alertIDs, eventIDs, entities)
	return f, nil
}

func applyFindingNulls(f *Finding, desc, detID, detName, dedup, user, host, srcIP, dstIP, ds, tactic, technique, owner, tags, alertIDs, eventIDs, entities sql.NullString) {
	f.Description = desc.String
	f.DetectionID = detID.String
	f.DetectionName = detName.String
	f.DedupKey = dedup.String
	f.User = user.String
	f.Host = host.String
	f.SourceIP = srcIP.String
	f.DestinationIP = dstIP.String
	f.DataSource = ds.String
	f.MITRETactic = tactic.String
	f.MITRETechnique = technique.String
	f.Owner = owner.String
	f.Tags = decodeStrings(tags.String)
	f.AlertIDs = decodeStrings(alertIDs.String)
	f.EventIDs = decodeStrings(eventIDs.String)
	f.Entities = decodeStrings(entities.String)
	if f.Tags == nil {
		f.Tags = []string{}
	}
	if f.AlertIDs == nil {
		f.AlertIDs = []string{}
	}
	if f.EventIDs == nil {
		f.EventIDs = []string{}
	}
	if f.Entities == nil {
		f.Entities = []string{}
	}
}

// GetByID retrieves a finding with its notes.
func (s *Store) GetByID(ctx context.Context, id string) (*Finding, error) {
	if id == "" {
		return nil, fmt.Errorf("empty finding ID")
	}
	f, err := scanFinding(s.db.QueryRowContext(ctx, findingSelectSQL+` WHERE id = ?`, id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("finding %s not found", id)
		}
		return nil, fmt.Errorf("query finding: %w", err)
	}
	notes, err := s.GetNotes(ctx, id)
	if err != nil {
		return nil, err
	}
	f.Notes = notes
	return f, nil
}

// List returns findings matching the filter, server-side.
func (s *Store) List(ctx context.Context, filter Filter) ([]*Finding, int, error) {
	if filter.Limit <= 0 || filter.Limit > maxFindingLimit {
		filter.Limit = 100
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	if filter.SortBy == "" {
		filter.SortBy = "last_seen"
	}
	if filter.SortOrder == "" || (filter.SortOrder != "asc" && filter.SortOrder != "desc") {
		filter.SortOrder = "desc"
	}

	where := []string{"1=1"}
	var args []any

	addEq := func(col, val string) {
		if val != "" {
			where = append(where, col+" = ?")
			args = append(args, val)
		}
	}
	addEq("severity", filter.Severity)
	addEq("status", filter.Status)
	addEq("owner", filter.Owner)
	addEq("detection_id", filter.DetectionID)
	addEq("user", filter.User)
	addEq("host", filter.Host)
	addEq("source_ip", filter.SourceIP)
	addEq("destination_ip", filter.DestIP)
	addEq("mitre_tactic", filter.Tactic)
	addEq("mitre_technique", filter.Technique)
	addEq("data_source", filter.Source)

	if filter.RiskMin > 0 || filter.HasRisk {
		where = append(where, "risk_score > ?")
		args = append(args, 0.0)
	}
	if filter.RiskMin > 0 {
		where = append(where, "risk_score >= ?")
		args = append(args, filter.RiskMin)
	}
	if filter.Text != "" {
		where = append(where, `(lower(title) LIKE lower(?) OR lower(detection_name) LIKE lower(?) OR lower(coalesce(owner,'')) LIKE lower(?))`)
		like := "%" + filter.Text + "%"
		args = append(args, like, like, like)
	}
	if filter.Tag != "" {
		where = append(where, `tags LIKE ?`)
		args = append(args, `%"`+strings.ReplaceAll(filter.Tag, `"`, "")+`"%`)
	}
	if !filter.Start.IsZero() {
		where = append(where, "last_seen >= ?")
		args = append(args, filter.Start.UTC())
	}
	if !filter.End.IsZero() {
		where = append(where, "last_seen <= ?")
		args = append(args, filter.End.UTC())
	}

	whereSQL := strings.Join(where, " AND ")

	sortCol := "last_seen"
	switch filter.SortBy {
	case "risk_score", "last_seen", "first_seen", "created_at", "severity", "title", "match_count":
		sortCol = filter.SortBy
	}
	sortDir := "DESC"
	if strings.EqualFold(filter.SortOrder, "asc") {
		sortDir = "ASC"
	}

	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM findings WHERE `+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count findings: %w", err)
	}

	rows, err := s.db.QueryContext(ctx,
		findingSelectSQL+` WHERE `+whereSQL+` ORDER BY `+sortCol+` `+sortDir+
			fmt.Sprintf(" LIMIT %d OFFSET %d", filter.Limit, filter.Offset), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()

	var out []*Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan finding: %w", err)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate findings: %w", err)
	}
	if out == nil {
		out = []*Finding{}
	}
	return out, total, nil
}

// Update persists mutable fields of a finding.
func (s *Store) Update(ctx context.Context, f *Finding) error {
	if f == nil || f.ID == "" {
		return fmt.Errorf("empty finding ID")
	}
	f.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`UPDATE findings SET title = ?, description = ?, severity = ?, status = ?, risk_score = ?,
		  detection_id = ?, detection_name = ?, user = ?, host = ?, source_ip = ?, destination_ip = ?,
		  data_source = ?, mitre_tactic = ?, mitre_technique = ?, owner = ?, tags = ?, alert_ids = ?,
		  event_ids = ?, entities = ?, match_count = ?, first_seen = ?, last_seen = ?, updated_at = ?
		 WHERE id = ?`,
		f.Title, nullStr(f.Description), f.Severity, f.Status, f.RiskScore,
		nullStr(f.DetectionID), nullStr(f.DetectionName), nullStr(f.User), nullStr(f.Host),
		nullStr(f.SourceIP), nullStr(f.DestinationIP), nullStr(f.DataSource),
		nullStr(f.MITRETactic), nullStr(f.MITRETechnique), nullStr(f.Owner),
		encodeStrings(f.Tags), encodeStrings(f.AlertIDs), encodeStrings(f.EventIDs), encodeStrings(f.Entities),
		f.MatchCount, f.FirstSeen, f.LastSeen, f.UpdatedAt, f.ID,
	)
	if err != nil {
		return fmt.Errorf("update finding: %w", err)
	}
	return nil
}

// UpdateStatus moves a finding through its lifecycle.
func (s *Store) UpdateStatus(ctx context.Context, id, status string) error {
	if !ValidStatus(status) {
		return fmt.Errorf("invalid finding status %q", status)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE findings SET status = ?, updated_at = ? WHERE id = ?`, status, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("update finding status: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("finding %s not found", id)
	}
	return nil
}

// Assign sets the finding owner.
func (s *Store) Assign(ctx context.Context, id, owner string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE findings SET owner = ?, updated_at = ? WHERE id = ?`, nullStr(owner), time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("assign finding: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("finding %s not found", id)
	}
	return nil
}

// AddNote appends an analyst note to a finding.
func (s *Store) AddNote(ctx context.Context, note *Note) error {
	if note == nil {
		return fmt.Errorf("nil note")
	}
	if note.FindingID == "" {
		return fmt.Errorf("empty finding ID")
	}
	if note.Content == "" {
		return fmt.Errorf("empty note content")
	}
	if note.ID == "" {
		note.ID = uuid.New().String()
	}
	note.CreatedAt = time.Now().UTC()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO finding_notes (id, finding_id, created_at, content, author) VALUES (?, ?, ?, ?, ?)`,
		note.ID, note.FindingID, note.CreatedAt, note.Content, nullStr(note.Author),
	)
	if err != nil {
		return fmt.Errorf("add finding note: %w", err)
	}
	return nil
}

// GetNotes returns all notes for a finding in chronological order.
func (s *Store) GetNotes(ctx context.Context, findingID string) ([]Note, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, finding_id, created_at, content, author FROM finding_notes
		 WHERE finding_id = ? ORDER BY created_at ASC`, findingID)
	if err != nil {
		return nil, fmt.Errorf("query finding notes: %w", err)
	}
	defer rows.Close()

	var notes []Note
	for rows.Next() {
		var n Note
		var author sql.NullString
		if err := rows.Scan(&n.ID, &n.FindingID, &n.CreatedAt, &n.Content, &author); err != nil {
			return nil, fmt.Errorf("scan note: %w", err)
		}
		n.Author = author.String
		notes = append(notes, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate notes: %w", err)
	}
	return notes, nil
}

// Posture returns queue posture counts for the SOC overview.
func (s *Store) Posture(ctx context.Context) (map[string]int, error) {
	out := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "open": 0}

	rows, err := s.db.QueryContext(ctx, `SELECT severity, COUNT(*) FROM findings GROUP BY severity`)
	if err != nil {
		return nil, fmt.Errorf("count findings by severity: %w", err)
	}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err == nil {
			out[Severity(sev)] += n
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate severity counts: %w", err)
	}

	var open int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM findings WHERE status NOT IN ('resolved', 'false_positive')`).Scan(&open); err != nil {
		return nil, fmt.Errorf("count open findings: %w", err)
	}
	out["open"] = open

	statusRows, err := s.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM findings GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("count findings by status: %w", err)
	}
	for statusRows.Next() {
		var st string
		var n int
		if err := statusRows.Scan(&st, &n); err == nil {
			out["status_"+st] = n
		}
	}
	statusRows.Close()
	if err := statusRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate status counts: %w", err)
	}

	return out, nil
}

// TimelinePoint is one bucket of findings created by first_seen.
type TimelinePoint struct {
	Bucket int64 `json:"bucket"`
	Count  int   `json:"count"`
}

// Timeline returns new-finding counts bucketed by first_seen over the window.
func (s *Store) Timeline(ctx context.Context, start, end time.Time, bucket time.Duration) ([]TimelinePoint, error) {
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
		`SELECT (strftime('%s', first_seen) / ?) * ? AS bucket, COUNT(*)
		 FROM findings
		 WHERE first_seen >= ? AND first_seen <= ?
		 GROUP BY bucket ORDER BY bucket`, sec, sec, start, end)
	if err != nil {
		return nil, fmt.Errorf("query finding timeline: %w", err)
	}
	defer rows.Close()

	var out []TimelinePoint
	for rows.Next() {
		var p TimelinePoint
		if err := rows.Scan(&p.Bucket, &p.Count); err != nil {
			return nil, fmt.Errorf("scan finding timeline row: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate finding timeline: %w", err)
	}
	return out, nil
}

// ActiveTechnique is one in-play ATT&CK technique with an open-finding count.
type ActiveTechnique struct {
	Tactic    string `json:"tactic"`
	Technique string `json:"technique"`
	Count     int    `json:"count"`
}

// ActiveTechniques lists distinct MITRE techniques carried by open findings.
func (s *Store) ActiveTechniques(ctx context.Context) ([]ActiveTechnique, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT mitre_tactic, mitre_technique, COUNT(*)
		 FROM findings
		 WHERE mitre_technique != '' AND status NOT IN ('resolved', 'false_positive')
		 GROUP BY mitre_tactic, mitre_technique
		 ORDER BY COUNT(*) DESC, mitre_technique`)
	if err != nil {
		return nil, fmt.Errorf("query active techniques: %w", err)
	}
	defer rows.Close()

	var out []ActiveTechnique
	for rows.Next() {
		var t ActiveTechnique
		if err := rows.Scan(&t.Tactic, &t.Technique, &t.Count); err != nil {
			return nil, fmt.Errorf("scan active technique: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active techniques: %w", err)
	}
	return out, nil
}

// RelatedByEntity returns open findings that touch an entity, newest first.
// Supported types: user, host, ip (source or destination).
func (s *Store) RelatedByEntity(ctx context.Context, entityType, value string, limit int) ([]*Finding, error) {
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	var where string
	var args []any
	switch entityType {
	case "user":
		where = "user = ?"
		args = []any{value}
	case "host":
		where = "host = ?"
		args = []any{value}
	case "ip":
		where = "(source_ip = ? OR destination_ip = ?)"
		args = []any{value, value}
	default:
		return nil, nil
	}
	if value == "" {
		return nil, nil
	}

	rows, err := s.db.QueryContext(ctx,
		findingSelectSQL+` WHERE `+where+` AND status NOT IN ('resolved', 'false_positive')
		 ORDER BY last_seen DESC LIMIT ?`,
		append(args, limit)...)
	if err != nil {
		return nil, fmt.Errorf("query related findings: %w", err)
	}
	defer rows.Close()

	var out []*Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("scan related finding: %w", err)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate related findings: %w", err)
	}
	return out, nil
}

// rowScanner is the common sql.Row/sql.Rows Scan interface.
type rowScanner interface {
	Scan(dest ...any) error
}

func primaryEntities(evs []*event.Event) (user, host, srcIP, dstIP string) {
	for _, ev := range evs {
		if ev == nil {
			continue
		}
		if user == "" {
			user = ev.User
		}
		if host == "" {
			host = ev.Host
		}
		if srcIP == "" {
			srcIP = ev.SourceIP
		}
		if dstIP == "" {
			dstIP = ev.DestinationIP
		}
		if user != "" && host != "" && srcIP != "" && dstIP != "" {
			break
		}
	}
	return user, host, srcIP, dstIP
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func encodeStrings(list []string) string {
	if len(list) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(list)
	return string(b)
}

func decodeStrings(s string) []string {
	if s == "" || s == "null" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}

// mergeStrings appends new items to base without duplicates, capping length.
func mergeStrings(base, add []string, cap int) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(base)+len(add))
	for _, v := range base {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	for _, v := range add {
		if len(out) >= cap {
			break
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
