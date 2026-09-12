package risk

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// EntityRiskStore persists accumulated per-entity risk and its transparent
// breakdown into contributions.
type EntityRiskStore struct {
	db *sql.DB
}

// EntityRisk is the current accumulated risk for one entity.
type EntityRisk struct {
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	RiskScore float64   `json:"risk_score"`
	Findings  int       `json:"findings"`
	Updated   time.Time `json:"updated_at"`
}

// Contribution is a single risk observation that added points to an entity.
type Contribution struct {
	ID          string    `json:"id"`
	EntityType  string    `json:"entity_type"`
	EntityValue string    `json:"entity_value"`
	SourceType  string    `json:"source_type"`
	SourceID    string    `json:"source_id,omitempty"`
	Description string    `json:"description,omitempty"`
	Points      float64   `json:"points"`
	EventID     string    `json:"event_id,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// NewEntityRiskStore creates the store. Tables are installed lazily on first
// use so the store can be constructed before migrations have run in tests.
func NewEntityRiskStore(db *sql.DB) *EntityRiskStore {
	return &EntityRiskStore{db: db}
}

func (s *EntityRiskStore) init(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS entity_risk (
			entity_type TEXT NOT NULL,
			entity_value TEXT NOT NULL,
			risk_score REAL NOT NULL DEFAULT 0,
			contribution_count INTEGER NOT NULL DEFAULT 0,
			updated_at DATETIME NOT NULL,
			PRIMARY KEY (entity_type, entity_value)
		)`,
		`CREATE TABLE IF NOT EXISTS risk_contributions (
			id TEXT PRIMARY KEY,
			entity_type TEXT NOT NULL,
			entity_value TEXT NOT NULL,
			source_type TEXT NOT NULL,
			source_id TEXT,
			description TEXT,
			points REAL NOT NULL,
			event_id TEXT,
			created_at DATETIME NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_risk_contributions_entity ON risk_contributions(entity_type, entity_value, created_at)`,
	}
	for _, q := range queries {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("init entity risk schema: %w", err)
		}
	}
	return nil
}

// Record adds a risk contribution for an entity and refreshes the aggregate.
// sourceType is one of: finding, event, action.
func (s *EntityRiskStore) Record(ctx context.Context, c Contribution) error {
	if err := s.init(ctx); err != nil {
		return err
	}
	if c.EntityType == "" || c.EntityValue == "" {
		return fmt.Errorf("entity type and value required")
	}
	if c.SourceType == "" {
		c.SourceType = "event"
	}
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	c.CreatedAt = time.Now().UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin risk record: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	srcID := c.SourceID
	evtID := c.EventID
	_, err = tx.ExecContext(ctx,
		`INSERT INTO risk_contributions (id, entity_type, entity_value, source_type, source_id, description, points, event_id, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.EntityType, c.EntityValue, c.SourceType, nullable(srcID), nullable(c.Description), c.Points, nullable(evtID), c.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert contribution: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO entity_risk (entity_type, entity_value, risk_score, contribution_count, updated_at)
		 VALUES (?, ?, ?, 1, ?)
		 ON CONFLICT(entity_type, entity_value) DO UPDATE SET
			risk_score = risk_score + excluded.risk_score,
			contribution_count = contribution_count + 1,
			updated_at = excluded.updated_at`,
		c.EntityType, c.EntityValue, c.Points, c.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("upsert entity risk: %w", err)
	}

	return tx.Commit()
}

// Get returns the accumulated risk for an entity. Nil when no risk recorded.
func (s *EntityRiskStore) Get(ctx context.Context, entityType, value string) (*EntityRisk, error) {
	if err := s.init(ctx); err != nil {
		return nil, err
	}
	var er EntityRisk
	err := s.db.QueryRowContext(ctx,
		`SELECT entity_type, entity_value, risk_score, contribution_count, updated_at
		 FROM entity_risk WHERE entity_type = ? AND entity_value = ?`,
		entityType, value,
	).Scan(&er.Type, &er.Value, &er.RiskScore, &er.Findings, &er.Updated)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get entity risk: %w", err)
	}
	return &er, nil
}

// Top returns the highest-risk entities of a type, with open finding counts.
func (s *EntityRiskStore) Top(ctx context.Context, entityType string, limit int) ([]EntityRisk, error) {
	if err := s.init(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	col, ok := safeEntityColumn(entityType)
	if !ok {
		return nil, fmt.Errorf("unsupported entity type %q for top risk", entityType)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT e.entity_type, e.entity_value, e.risk_score, COALESCE(f.cnt, 0), e.updated_at
		 FROM entity_risk e
		 LEFT JOIN (
		    SELECT ` + col + ` AS entity_value, COUNT(*) AS cnt FROM findings
		    WHERE status NOT IN ('resolved', 'false_positive') GROUP BY ` + col + `
		 ) f ON f.entity_value = e.entity_value
		 WHERE e.entity_type = ?
		 ORDER BY e.risk_score DESC
		 LIMIT ?`,
		entityType, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query top risk: %w", err)
	}
	defer rows.Close()

	var out []EntityRisk
	for rows.Next() {
		var er EntityRisk
		if err := rows.Scan(&er.Type, &er.Value, &er.RiskScore, &er.Findings, &er.Updated); err != nil {
			return nil, fmt.Errorf("scan top risk row: %w", err)
		}
		out = append(out, er)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate top risk: %w", err)
	}
	return out, nil
}

// ContributedFindings counts open findings touching an entity.
func (s *EntityRiskStore) ContributedFindings(ctx context.Context, entityType, value string) (int, error) {
	if err := s.init(ctx); err != nil {
		return 0, err
	}
	col, ok := safeEntityColumn(entityType)
	if !ok {
		return 0, nil
	}
	var n int
	err := s.db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT COUNT(*) FROM findings WHERE %s = ? AND status NOT IN ('resolved','false_positive')`, col),
		value,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count findings for entity: %w", err)
	}
	return n, nil
}

// Contributions lists the risk contributions of an entity, newest first.
func (s *EntityRiskStore) Contributions(ctx context.Context, entityType, value string, limit int) ([]Contribution, error) {
	if err := s.init(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, entity_type, entity_value, source_type, source_id, description, points, event_id, created_at
		 FROM risk_contributions WHERE entity_type = ? AND entity_value = ?
		 ORDER BY created_at DESC LIMIT ?`,
		entityType, value, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query contributions: %w", err)
	}
	defer rows.Close()

	var out []Contribution
	for rows.Next() {
		var c Contribution
		var srcID, desc, evtID sql.NullString
		if err := rows.Scan(&c.ID, &c.EntityType, &c.EntityValue, &c.SourceType, &srcID, &desc, &c.Points, &evtID, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan contribution: %w", err)
		}
		c.SourceID = srcID.String
		c.Description = desc.String
		c.EventID = evtID.String
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate contributions: %w", err)
	}
	return out, nil
}

// AtRisk counts entities of a type carrying any recorded risk.
func (s *EntityRiskStore) AtRisk(ctx context.Context, entityType string) (int, error) {
	if err := s.init(ctx); err != nil {
		return 0, err
	}
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM entity_risk WHERE entity_type = ? AND risk_score > 0`, entityType,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count at-risk entities: %w", err)
	}
	return n, nil
}

func safeEntityColumn(entityType string) (string, bool) {
	switch entityType {
	case "user":
		return "user", true
	case "host":
		return "host", true
	case "ip":
		return "source_ip", true
	}
	return "", false
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
