package ai

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Statuses is the AI Analyst analysis lifecycle.
//
//	analyzing -> analyzed -> approved | dismissed
//	           \-> failed -> (re-analyzing overwrites the row)
//
// There is deliberately no execution state: the analyst only records
// recommendations; acting on them requires a separate human-approved flow.
var Statuses = []string{"analyzing", "analyzed", "failed", "approved", "dismissed"}

// Decisions are the human-in-the-loop outcomes.
var Decisions = []string{"approve", "dismiss"}

// Row is one AI analysis record (one per finding).
type Row struct {
	ID                 string    `json:"id"`
	FindingID          string    `json:"finding_id"`
	Status             string    `json:"status"`
	Provider           string    `json:"provider,omitempty"`
	Model              string    `json:"model,omitempty"`
	PromptVersion      string    `json:"prompt_version,omitempty"`
	PromptHash         string    `json:"prompt_hash,omitempty"`
	Error              string    `json:"error,omitempty"`
	Confidence         float64   `json:"confidence"`
	Severity           string    `json:"severity,omitempty"`
	RecommendationType string    `json:"recommended_action_type,omitempty"`
	Decision           string    `json:"decision,omitempty"`
	DecisionReason     string    `json:"decision_reason,omitempty"`
	DecidedBy          string    `json:"decided_by,omitempty"`
	DecidedAt          time.Time `json:"decided_at,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	// FindingTitle/Severity/Status are joined in from the finding for lists.
	FindingTitle    string `json:"finding_title,omitempty"`
	FindingSeverity string `json:"finding_severity,omitempty"`
	FindingStatus   string `json:"finding_status,omitempty"`
}

// ListFilter filters analysis listings.
type ListFilter struct {
	Status   string
	Severity string
	Limit    int
	Offset   int
}

const maxAILimit = 200

// ErrNotFound is returned when an analysis id does not exist.
var ErrNotFound = errors.New("ai analysis not found")

// Store persists AI analysis records.
type Store struct {
	db *sql.DB
}

// NewStore creates the AI analyst store on the given database.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

// CreateArgs carries everything known when an analysis starts.
type CreateArgs struct {
	FindingID     string
	Provider      string
	Model         string
	PromptVersion string
	PromptHash    string
	ContextJSON   string
}

// CreateOrReset starts a new analysis for the finding or resets the existing
// one (re-analysis after new evidence or after a failure). A previous human
// decision is cleared because a new analysis requires a new decision.
func (s *Store) CreateOrReset(ctx context.Context, args CreateArgs) (*Row, error) {
	if args.FindingID == "" {
		return nil, fmt.Errorf("finding_id is required")
	}
	now := time.Now().UTC()
	id := uuid.New().String()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ai_analyses (
			id, finding_id, status, provider, model,
			prompt_version, prompt_hash, context,
			created_at, updated_at
		) VALUES (?, ?, 'analyzing', ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(finding_id) DO UPDATE SET
			status = 'analyzing',
			provider = excluded.provider,
			model = excluded.model,
			prompt_version = excluded.prompt_version,
			prompt_hash = excluded.prompt_hash,
			context = excluded.context,
			analysis = NULL,
			error = NULL,
			confidence = 0,
			severity = NULL,
			recommendation_type = NULL,
			decision = '',
			decision_reason = '',
			decided_by = '',
			decided_at = NULL,
			updated_at = excluded.updated_at
	`,
		id, args.FindingID, args.Provider, args.Model,
		args.PromptVersion, args.PromptHash, args.ContextJSON,
		now, now,
	)
	if err != nil {
		// ON CONFLICT keeps the original row id; fetch the active one.
		if active, aerr := s.ActiveByFinding(ctx, args.FindingID); aerr == nil {
			return active, nil
		}
		return nil, fmt.Errorf("create ai analysis: %w", err)
	}
	return s.ActiveByFinding(ctx, args.FindingID)
}

// Complete stores a validated analysis and moves the row to "analyzed".
func (s *Store) Complete(ctx context.Context, id string, a *Analysis) error {
	analysisJSON, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("marshal analysis: %w", err)
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE ai_analyses SET
			status = 'analyzed',
			analysis = ?,
			error = NULL,
			confidence = ?,
			severity = ?,
			recommendation_type = ?,
			updated_at = ?
		WHERE id = ? AND status IN ('analyzing','failed','analyzed')
	`, string(analysisJSON), a.Confidence, a.Severity, a.RecommendedAction.Type, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("complete ai analysis: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("ai analysis %s is not open for completion", id)
	}
	return nil
}

// Fail records a provider/validation failure. The row keeps its context so
// the operator can retry without rebuilding.
func (s *Store) Fail(ctx context.Context, id, errMsg string) error {
	if _, err := s.db.ExecContext(ctx, `
		UPDATE ai_analyses SET status = 'failed', error = ?, updated_at = ?
		WHERE id = ? AND status = 'analyzing'
	`, errMsg, time.Now().UTC(), id); err != nil {
		return fmt.Errorf("fail ai analysis: %w", err)
	}
	return nil
}

// Decide records the human decision. Only "analyzed" analyses can be
// decided; this is the human-in-the-loop gate.
func (s *Store) Decide(ctx context.Context, id, decision, reason, actor string) error {
	if decision != "approve" && decision != "dismiss" {
		return fmt.Errorf("decision must be %s", "approve or dismiss")
	}
	status := "approved"
	if decision == "dismiss" {
		status = "dismissed"
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE ai_analyses SET
			status = ?, decision = ?, decision_reason = ?,
			decided_by = ?, decided_at = ?, updated_at = ?
		WHERE id = ? AND status = 'analyzed'
	`, status, decision, reason, actor, time.Now().UTC(), time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("decide ai analysis: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("ai analysis %s is not awaiting a decision", id)
	}
	return nil
}

// ActiveByFinding returns the analysis row for a finding (there is at most
// one per finding).
func (s *Store) ActiveByFinding(ctx context.Context, findingID string) (*Row, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, finding_id, status, COALESCE(provider,''), COALESCE(model,''),
		       COALESCE(prompt_version,''), COALESCE(prompt_hash,''),
		       COALESCE(error,''), COALESCE(confidence,0),
		       COALESCE(severity,''), COALESCE(recommendation_type,''),
		       COALESCE(decision,''), COALESCE(decision_reason,''),
		       COALESCE(decided_by,''), decided_at,
		       created_at, updated_at
		FROM ai_analyses WHERE finding_id = ?
	`, findingID)
	return scanAIAnalysis(row)
}

// Get returns the full detail (row, analysis payload, evidence context).
// The caller loads the underlying finding via the finding store.
func (s *Store) Get(ctx context.Context, id string) (*Row, *Analysis, *FindingContext, error) {
	var (
		r            Row
		decidedAt    sql.NullTime
		analysisJSON sql.NullString
		contextJSON  sql.NullString
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, finding_id, status, COALESCE(provider,''), COALESCE(model,''),
		       COALESCE(prompt_version,''), COALESCE(prompt_hash,''),
		       COALESCE(error,''), COALESCE(confidence,0),
		       COALESCE(severity,''), COALESCE(recommendation_type,''),
		       COALESCE(decision,''), COALESCE(decision_reason,''),
		       COALESCE(decided_by,''), decided_at,
		       created_at, updated_at, analysis, context
		FROM ai_analyses WHERE id = ?
	`, id).Scan(
		&r.ID, &r.FindingID, &r.Status, &r.Provider, &r.Model,
		&r.PromptVersion, &r.PromptHash, &r.Error, &r.Confidence,
		&r.Severity, &r.RecommendationType, &r.Decision, &r.DecisionReason,
		&r.DecidedBy, &decidedAt, &r.CreatedAt, &r.UpdatedAt,
		&analysisJSON, &contextJSON,
	)
	if err == sql.ErrNoRows {
		return nil, nil, nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get ai analysis: %w", err)
	}
	if decidedAt.Valid {
		r.DecidedAt = decidedAt.Time
	} else {
		r.DecidedAt = r.CreatedAt
	}

	var a *Analysis
	if analysisJSON.Valid && analysisJSON.String != "" {
		a = &Analysis{}
		if err := json.Unmarshal([]byte(analysisJSON.String), a); err != nil {
			return nil, nil, nil, fmt.Errorf("corrupt stored analysis: %w", err)
		}
	}
	var c *FindingContext
	if contextJSON.Valid && contextJSON.String != "" {
		c = &FindingContext{}
		_ = json.Unmarshal([]byte(contextJSON.String), c) // context is advisory; never fail the read
	}
	return &r, a, c, nil
}

// List returns analyses (newest first) with their finding summary.
func (s *Store) List(ctx context.Context, f ListFilter) ([]*Row, int, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	if f.Limit > maxAILimit {
		f.Limit = maxAILimit
	}
	if f.Offset < 0 {
		f.Offset = 0
	}

	where := " WHERE 1=1"
	var args []any
	if f.Status != "" {
		where += " AND a.status = ?"
		args = append(args, f.Status)
	}
	if f.Severity != "" {
		where += " AND a.severity = ?"
		args = append(args, f.Severity)
	}

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM ai_analyses a"+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count ai analyses: %w", err)
	}

	q := `
		SELECT a.id, a.finding_id, a.status,
		       COALESCE(a.provider,''), COALESCE(a.model,''),
		       COALESCE(a.prompt_version,''), COALESCE(a.prompt_hash,''),
		       COALESCE(a.error,''), COALESCE(a.confidence,0),
		       COALESCE(a.severity,''), COALESCE(a.recommendation_type,''),
		       COALESCE(a.decision,''), COALESCE(a.decision_reason,''),
		       COALESCE(a.decided_by,''), a.decided_at,
		       a.created_at, a.updated_at,
		       COALESCE(f.title,''), COALESCE(f.severity,''), COALESCE(f.status,'')
		FROM ai_analyses a
		LEFT JOIN findings f ON f.id = a.finding_id` + where +
		" ORDER BY a.updated_at DESC LIMIT ? OFFSET ?"
	args = append(args, f.Limit, f.Offset)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list ai analyses: %w", err)
	}
	defer rows.Close()

	var out []*Row
	for rows.Next() {
		var r Row
		var decidedAt sql.NullTime
		if err := rows.Scan(
			&r.ID, &r.FindingID, &r.Status, &r.Provider, &r.Model,
			&r.PromptVersion, &r.PromptHash, &r.Error, &r.Confidence,
			&r.Severity, &r.RecommendationType, &r.Decision, &r.DecisionReason,
			&r.DecidedBy, &decidedAt, &r.CreatedAt, &r.UpdatedAt,
			&r.FindingTitle, &r.FindingSeverity, &r.FindingStatus,
		); err != nil {
			return nil, 0, fmt.Errorf("scan ai analysis: %w", err)
		}
		if decidedAt.Valid {
			r.DecidedAt = decidedAt.Time
		} else {
			r.DecidedAt = r.CreatedAt
		}
		out = append(out, &r)
	}
	return out, total, rows.Err()
}

// Stats counts rows per status (for badges / overview).
func (s *Store) Stats(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT status, COUNT(*) FROM ai_analyses GROUP BY status")
	if err != nil {
		return nil, fmt.Errorf("ai analysis stats: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}

// scanAIAnalysis scans a row whose 15th column is the nullable decided_at.
// DecidedAt falls back to CreatedAt when the analysis was never decided so the
// API always has a non-zero timestamp.
func scanAIAnalysis(row *sql.Row) (*Row, error) {
	var r Row
	var decidedAt sql.NullTime
	err := row.Scan(
		&r.ID, &r.FindingID, &r.Status, &r.Provider, &r.Model,
		&r.PromptVersion, &r.PromptHash, &r.Error, &r.Confidence,
		&r.Severity, &r.RecommendationType, &r.Decision, &r.DecisionReason,
		&r.DecidedBy, &decidedAt, &r.CreatedAt, &r.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan ai analysis: %w", err)
	}
	if decidedAt.Valid {
		r.DecidedAt = decidedAt.Time
	} else {
		r.DecidedAt = r.CreatedAt
	}
	return &r, nil
}
