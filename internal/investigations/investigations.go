// Package investigations implements the persistent analyst workbench:
// investigations that collect findings, events, entities, queries, techniques
// and authored notes into a single security story.
package investigations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Investigation is a persistent security story assembled by an analyst.
type Investigation struct {
	ID         string    `json:"id"`
	Title      string    `json:"title"`
	Description string   `json:"description"`
	Severity   string    `json:"severity"`
	Status     string    `json:"status"`
	Assignee   string    `json:"assignee,omitempty"`
	FindingIDs []string  `json:"finding_ids"`
	EventIDs   []string  `json:"event_ids"`
	Entities   []Entity  `json:"entities"`
	Queries    []string  `json:"queries"`
	Techniques []string  `json:"techniques"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	Notes      []Note    `json:"notes"`
}

// Entity is a typed entity reference held by an investigation.
type Entity struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Note is an authored timeline entry (timestamp + author + investigation id).
type Note struct {
	ID             string    `json:"id"`
	InvestigationID string   `json:"investigation_id"`
	Author         string    `json:"author"`
	Body           string    `json:"body"`
	CreatedAt      time.Time `json:"created_at"`
}

// Statuses is the investigation lifecycle.
var Statuses = []string{"new", "in_progress", "contained", "resolved", "false_positive", "cancelled"}

// ValidStatus reports whether s is part of the investigation lifecycle.
func ValidStatus(s string) bool {
	for _, v := range Statuses {
		if v == s {
			return true
		}
	}
	return false
}

// Store persists investigations.
type Store struct {
	db *sql.DB
}

// NewStore creates an investigation store.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// Filter carries listing parameters.
type Filter struct {
	Severity string
	Status   string
	Assignee string
	Limit    int
	Offset   int
}

const selectSQL = `SELECT id, title, description, severity, status, assignee,
       finding_ids, event_ids, entities, queries, techniques, created_at, updated_at
       FROM investigations`

// Create inserts a new investigation.
func (s *Store) Create(ctx context.Context, in *Investigation) error {
	if in == nil || in.Title == "" {
		return fmt.Errorf("investigation title required")
	}
	if in.ID == "" {
		in.ID = uuid.New().String()
	}
	if in.Status == "" {
		in.Status = "new"
	}
	now := time.Now().UTC()
	in.CreatedAt = now
	in.UpdatedAt = now

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO investigations (id, title, description, severity, status, assignee,
		  finding_ids, event_ids, entities, queries, techniques, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		in.ID, in.Title, nullStr(in.Description), nullStr(in.Severity), in.Status, nullStr(in.Assignee),
		encodeStrings(in.FindingIDs), encodeStrings(in.EventIDs), encodeEntities(in.Entities),
		encodeStrings(in.Queries), encodeStrings(in.Techniques), in.CreatedAt, in.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("create investigation: %w", err)
	}
	return nil
}

// GetByID retrieves an investigation with its notes.
func (s *Store) GetByID(ctx context.Context, id string) (*Investigation, error) {
	if id == "" {
		return nil, fmt.Errorf("empty investigation ID")
	}
	in, err := scanInvestigation(s.db.QueryRowContext(ctx, selectSQL+` WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("investigation %s not found", id)
	}
	if err != nil {
		return nil, fmt.Errorf("query investigation: %w", err)
	}
	notes, err := s.ListNotes(ctx, id)
	if err != nil {
		return nil, err
	}
	in.Notes = notes
	return in, nil
}

// List returns investigations matching the filter.
func (s *Store) List(ctx context.Context, filter Filter) ([]*Investigation, int, error) {
	if filter.Limit <= 0 || filter.Limit > 500 {
		filter.Limit = 100
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}

	where := []string{"1=1"}
	var args []any
	if filter.Severity != "" {
		where = append(where, "severity = ?")
		args = append(args, filter.Severity)
	}
	if filter.Status != "" {
		where = append(where, "status = ?")
		args = append(args, filter.Status)
	}
	if filter.Assignee != "" {
		where = append(where, "assignee = ?")
		args = append(args, filter.Assignee)
	}
	whereSQL := strings.Join(where, " AND ")

	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM investigations WHERE `+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count investigations: %w", err)
	}

	rows, err := s.db.QueryContext(ctx,
		selectSQL+` WHERE `+whereSQL+` ORDER BY updated_at DESC LIMIT ? OFFSET ?`,
		append(args, filter.Limit, filter.Offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list investigations: %w", err)
	}
	defer rows.Close()

	var out []*Investigation
	for rows.Next() {
		in, err := scanInvestigation(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan investigation: %w", err)
		}
		out = append(out, in)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate investigations: %w", err)
	}
	if out == nil {
		out = []*Investigation{}
	}
	return out, total, nil
}

func scanInvestigation(row rowScanner) (*Investigation, error) {
	in := &Investigation{}
	var desc, sev, assignee sql.NullString
	var findingIDs, eventIDs, entities, queries, techniques sql.NullString
	err := row.Scan(
		&in.ID, &in.Title, &desc, &sev, &in.Status, &assignee,
		&findingIDs, &eventIDs, &entities, &queries, &techniques,
		&in.CreatedAt, &in.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	in.Description = desc.String
	in.Severity = sev.String
	in.Assignee = assignee.String
	in.FindingIDs = decodeStrings(findingIDs.String)
	in.EventIDs = decodeStrings(eventIDs.String)
	in.Entities = decodeEntities(entities.String)
	in.Queries = decodeStrings(queries.String)
	in.Techniques = decodeStrings(techniques.String)
	if in.FindingIDs == nil {
		in.FindingIDs = []string{}
	}
	if in.EventIDs == nil {
		in.EventIDs = []string{}
	}
	if in.Entities == nil {
		in.Entities = []Entity{}
	}
	if in.Queries == nil {
		in.Queries = []string{}
	}
	if in.Techniques == nil {
		in.Techniques = []string{}
	}
	return in, nil
}

// Update persists mutable fields of an investigation.
func (s *Store) Update(ctx context.Context, in *Investigation) error {
	if in == nil || in.ID == "" {
		return fmt.Errorf("empty investigation ID")
	}
	in.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`UPDATE investigations SET title = ?, description = ?, severity = ?, status = ?, assignee = ?,
		  finding_ids = ?, event_ids = ?, entities = ?, queries = ?, techniques = ?, updated_at = ?
		 WHERE id = ?`,
		in.Title, nullStr(in.Description), nullStr(in.Severity), in.Status, nullStr(in.Assignee),
		encodeStrings(in.FindingIDs), encodeStrings(in.EventIDs), encodeEntities(in.Entities),
		encodeStrings(in.Queries), encodeStrings(in.Techniques), in.UpdatedAt, in.ID,
	)
	if err != nil {
		return fmt.Errorf("update investigation: %w", err)
	}
	return nil
}

// UpdateStatus moves the investigation through its lifecycle.
func (s *Store) UpdateStatus(ctx context.Context, id, status string) error {
	if !ValidStatus(status) {
		return fmt.Errorf("invalid investigation status %q", status)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE investigations SET status = ?, updated_at = ? WHERE id = ?`, status, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("update investigation status: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("investigation %s not found", id)
	}
	return nil
}

// AddEvents associates event IDs (deduplicated, capped).
func (s *Store) AddEvents(ctx context.Context, id string, eventIDs []string) error {
	return s.mergeStringList(ctx, id, "event_ids", eventIDs, 500)
}

// AddFindings associates finding IDs.
func (s *Store) AddFindings(ctx context.Context, id string, findingIDs []string) error {
	return s.mergeStringList(ctx, id, "finding_ids", findingIDs, 200)
}

// AddQuery records a saved query used in the investigation.
func (s *Store) AddQuery(ctx context.Context, id, query string) error {
	if strings.TrimSpace(query) == "" {
		return fmt.Errorf("empty query")
	}
	return s.mergeStringList(ctx, id, "queries", []string{query}, 100)
}

// AddEntity records an entity reference.
func (s *Store) AddEntity(ctx context.Context, id string, e Entity) error {
	if e.Type == "" || e.Value == "" {
		return fmt.Errorf("entity type and value required")
	}
	in, err := s.GetByID(ctx, id)
	if err != nil {
		return err
	}
	for _, existing := range in.Entities {
		if existing.Type == e.Type && existing.Value == e.Value {
			return nil
		}
	}
	if len(in.Entities) >= 200 {
		return fmt.Errorf("entity limit reached for investigation")
	}
	in.Entities = append(in.Entities, e)
	return s.Update(ctx, in)
}

// AddTechnique records a MITRE technique touched by the investigation.
func (s *Store) AddTechnique(ctx context.Context, id, technique string) error {
	return s.mergeStringList(ctx, id, "techniques", []string{technique}, 50)
}

// AddNote appends an authored note.
func (s *Store) AddNote(ctx context.Context, note *Note) (*Note, error) {
	if note == nil {
		return nil, fmt.Errorf("nil note")
	}
	if note.InvestigationID == "" {
		return nil, fmt.Errorf("empty investigation ID")
	}
	if strings.TrimSpace(note.Body) == "" {
		return nil, fmt.Errorf("empty note body")
	}
	if len(note.Body) > 4000 {
		return nil, fmt.Errorf("note too long (max 4000 bytes)")
	}
	if note.ID == "" {
		note.ID = uuid.New().String()
	}
	note.CreatedAt = time.Now().UTC()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO investigation_notes (id, investigation_id, author, body, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		note.ID, note.InvestigationID, note.Author, note.Body, note.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("add investigation note: %w", err)
	}
	return note, nil
}

// ListNotes returns the notes of an investigation in chronological order.
func (s *Store) ListNotes(ctx context.Context, id string) ([]Note, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, investigation_id, author, body, created_at FROM investigation_notes
		 WHERE investigation_id = ? ORDER BY created_at ASC, id ASC`, id)
	if err != nil {
		return nil, fmt.Errorf("query investigation notes: %w", err)
	}
	defer rows.Close()

	var notes []Note
	for rows.Next() {
		var n Note
		if err := rows.Scan(&n.ID, &n.InvestigationID, &n.Author, &n.Body, &n.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan note: %w", err)
		}
		notes = append(notes, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate notes: %w", err)
	}
	return notes, nil
}

func (s *Store) mergeStringList(ctx context.Context, id, column string, add []string, cap int) error {
	in, err := s.GetByID(ctx, id)
	if err != nil {
		return err
	}
	var cur []string
	switch column {
	case "event_ids":
		cur = in.EventIDs
	case "finding_ids":
		cur = in.FindingIDs
	case "queries":
		cur = in.Queries
	case "techniques":
		cur = in.Techniques
	default:
		return fmt.Errorf("unsupported column %q", column)
	}
	seen := map[string]bool{}
	for _, v := range cur {
		seen[v] = true
	}
	for _, v := range add {
		if len(cur) >= cap {
			break
		}
		if !seen[v] {
			seen[v] = true
			cur = append(cur, v)
		}
	}
	switch column {
	case "event_ids":
		in.EventIDs = cur
	case "finding_ids":
		in.FindingIDs = cur
	case "queries":
		in.Queries = cur
	case "techniques":
		in.Techniques = cur
	}
	return s.Update(ctx, in)
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

func encodeEntities(list []Entity) string {
	if len(list) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(list)
	return string(b)
}

func decodeEntities(s string) []Entity {
	if s == "" || s == "null" {
		return nil
	}
	var out []Entity
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

type rowScanner interface {
	Scan(dest ...any) error
}
