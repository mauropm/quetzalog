package incidents

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Incident represents a security incident.
type Incident struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Assignee    string    `json:"assignee"`
	Description string    `json:"description"`
	AlertIDs    []string  `json:"alert_ids"`
	EventIDs    []string  `json:"event_ids"`
	EntityIDs   []string  `json:"entity_ids"`
}

// Store persists and queries incidents.
type Store struct {
	db *sql.DB
}

// Filter holds parameters for listing incidents.
type Filter struct {
	Severity string
	Status   string
	Limit    int
	Offset   int
}

// NewStore creates a new incident store backed by the given database.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// Create inserts a new incident.
func (s *Store) Create(ctx context.Context, inc *Incident) error {
	if inc == nil {
		return fmt.Errorf("nil incident provided")
	}

	if inc.ID == "" {
		inc.ID = uuid.New().String()
	}
	if inc.Severity == "" {
		inc.Severity = "medium"
	}
	if inc.Status == "" {
		inc.Status = "open"
	}
	inc.CreatedAt = time.Now()
	inc.UpdatedAt = time.Now()

	alertIDsJSON, _ := json.Marshal(inc.AlertIDs)
	eventIDsJSON, _ := json.Marshal(inc.EventIDs)
	entityIDsJSON, _ := json.Marshal(inc.EntityIDs)

	query := `INSERT INTO incidents (id, title, severity, status, created_at, updated_at, assignee, description, alert_ids, event_ids, entity_ids)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query,
		inc.ID,
		inc.Title,
		inc.Severity,
		inc.Status,
		inc.CreatedAt,
		inc.UpdatedAt,
		inc.Assignee,
		inc.Description,
		string(alertIDsJSON),
		string(eventIDsJSON),
		string(entityIDsJSON),
	)
	if err != nil {
		return fmt.Errorf("create incident: %w", err)
	}

	return nil
}

// GetByID retrieves an incident by its ID.
func (s *Store) GetByID(ctx context.Context, id string) (*Incident, error) {
	if id == "" {
		return nil, fmt.Errorf("empty incident ID")
	}

	query := `SELECT id, title, severity, status, created_at, updated_at, assignee, description, alert_ids, event_ids, entity_ids
	          FROM incidents WHERE id = ?`

	inc := &Incident{}
	var alertIDsJSON, eventIDsJSON, entityIDsJSON string
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&inc.ID,
		&inc.Title,
		&inc.Severity,
		&inc.Status,
		&inc.CreatedAt,
		&inc.UpdatedAt,
		&inc.Assignee,
		&inc.Description,
		&alertIDsJSON,
		&eventIDsJSON,
		&entityIDsJSON,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("incident %s not found", id)
		}
		return nil, fmt.Errorf("query incident %s: %w", id, err)
	}

	json.Unmarshal([]byte(alertIDsJSON), &inc.AlertIDs)
	json.Unmarshal([]byte(eventIDsJSON), &inc.EventIDs)
	json.Unmarshal([]byte(entityIDsJSON), &inc.EntityIDs)

	return inc, nil
}

// List returns incidents matching the given filter.
func (s *Store) List(ctx context.Context, filter Filter) ([]*Incident, error) {
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}

	query := `SELECT id, title, severity, status, created_at, updated_at, assignee, description, alert_ids, event_ids, entity_ids
	          FROM incidents WHERE 1=1`
	var args []any

	if filter.Severity != "" {
		query += " AND severity = ?"
		args = append(args, filter.Severity)
	}
	if filter.Status != "" {
		query += " AND status = ?"
		args = append(args, filter.Status)
	}
	query += " ORDER BY created_at DESC"
	query += fmt.Sprintf(" LIMIT %d OFFSET %d", filter.Limit, filter.Offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list incidents: %w", err)
	}
	defer rows.Close()

	var incidents []*Incident
	for rows.Next() {
		inc := &Incident{}
		var alertIDsJSON, eventIDsJSON, entityIDsJSON string
		err := rows.Scan(
			&inc.ID,
			&inc.Title,
			&inc.Severity,
			&inc.Status,
			&inc.CreatedAt,
			&inc.UpdatedAt,
			&inc.Assignee,
			&inc.Description,
			&alertIDsJSON,
			&eventIDsJSON,
			&entityIDsJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("scan incident row: %w", err)
		}
		json.Unmarshal([]byte(alertIDsJSON), &inc.AlertIDs)
		json.Unmarshal([]byte(eventIDsJSON), &inc.EventIDs)
		json.Unmarshal([]byte(entityIDsJSON), &inc.EntityIDs)
		incidents = append(incidents, inc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate incidents: %w", err)
	}

	return incidents, nil
}

// UpdateStatus changes the status of an incident.
func (s *Store) UpdateStatus(ctx context.Context, id, status string) error {
	if id == "" {
		return fmt.Errorf("empty incident ID")
	}
	if status == "" {
		return fmt.Errorf("empty status")
	}

	query := `UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, status, time.Now(), id)
	if err != nil {
		return fmt.Errorf("update incident status: %w", err)
	}

	return nil
}

// AddAlerts associates alert IDs with an incident.
func (s *Store) AddAlerts(ctx context.Context, incidentID string, alertIDs []string) error {
	if incidentID == "" {
		return fmt.Errorf("empty incident ID")
	}

	inc, err := s.GetByID(ctx, incidentID)
	if err != nil {
		return fmt.Errorf("get incident: %w", err)
	}

	// Merge and deduplicate alert IDs
	seen := make(map[string]bool)
	for _, id := range inc.AlertIDs {
		seen[id] = true
	}
	for _, id := range alertIDs {
		if !seen[id] {
			inc.AlertIDs = append(inc.AlertIDs, id)
			seen[id] = true
		}
	}

	alertIDsJSON, _ := json.Marshal(inc.AlertIDs)
	query := `UPDATE incidents SET alert_ids = ?, updated_at = ? WHERE id = ?`
	_, err = s.db.ExecContext(ctx, query, string(alertIDsJSON), time.Now(), incidentID)
	if err != nil {
		return fmt.Errorf("add alerts to incident: %w", err)
	}

	return nil
}

// AddEvents associates event IDs with an incident.
func (s *Store) AddEvents(ctx context.Context, incidentID string, eventIDs []string) error {
	if incidentID == "" {
		return fmt.Errorf("empty incident ID")
	}

	inc, err := s.GetByID(ctx, incidentID)
	if err != nil {
		return fmt.Errorf("get incident: %w", err)
	}

	seen := make(map[string]bool)
	for _, id := range inc.EventIDs {
		seen[id] = true
	}
	for _, id := range eventIDs {
		if !seen[id] {
			inc.EventIDs = append(inc.EventIDs, id)
			seen[id] = true
		}
	}

	eventIDsJSON, _ := json.Marshal(inc.EventIDs)
	query := `UPDATE incidents SET event_ids = ?, updated_at = ? WHERE id = ?`
	_, err = s.db.ExecContext(ctx, query, string(eventIDsJSON), time.Now(), incidentID)
	if err != nil {
		return fmt.Errorf("add events to incident: %w", err)
	}

	return nil
}

// Update updates an existing incident.
func (s *Store) Update(ctx context.Context, inc *Incident) error {
	if inc == nil {
		return fmt.Errorf("nil incident provided")
	}
	if inc.ID == "" {
		return fmt.Errorf("empty incident ID")
	}

	alertIDsJSON, _ := json.Marshal(inc.AlertIDs)
	eventIDsJSON, _ := json.Marshal(inc.EventIDs)
	entityIDsJSON, _ := json.Marshal(inc.EntityIDs)

	query := `UPDATE incidents SET title = ?, severity = ?, status = ?, assignee = ?, description = ?,
	          alert_ids = ?, event_ids = ?, entity_ids = ?, updated_at = ? WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query,
		inc.Title,
		inc.Severity,
		inc.Status,
		inc.Assignee,
		inc.Description,
		string(alertIDsJSON),
		string(eventIDsJSON),
		string(entityIDsJSON),
		time.Now(),
		inc.ID,
	)
	if err != nil {
		return fmt.Errorf("update incident: %w", err)
	}

	return nil
}
