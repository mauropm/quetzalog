package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// SavedView is a named, per-user analyst queue filter set.
type SavedView struct {
	ID        string    `json:"id"`
	User      string    `json:"user"`
	Name      string    `json:"name"`
	Filters   map[string]string `json:"filters"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SaveView persists a saved view for a user. A view with the same user and
// name is updated in place (stable ID) instead of duplicated.
func (s *Store) SaveView(ctx context.Context, v *SavedView) error {
	if v == nil || v.User == "" || v.Name == "" {
		return fmt.Errorf("view user and name required")
	}
	data, err := json.Marshal(v.Filters)
	if err != nil {
		data = []byte("{}")
	}
	now := time.Now().UTC()

	var existingID string
	err = s.db.QueryRowContext(ctx,
		`SELECT id FROM saved_views WHERE user = ? AND name = ?`, v.User, v.Name,
	).Scan(&existingID)
	if err == nil {
		v.ID = existingID
		if _, err := s.db.ExecContext(ctx,
			`UPDATE saved_views SET filters = ?, updated_at = ? WHERE id = ?`,
			string(data), now, v.ID); err != nil {
			return fmt.Errorf("update view: %w", err)
		}
		v.UpdatedAt = now
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("lookup view: %w", err)
	}

	if v.ID == "" {
		v.ID = uuid.New().String()
	}
	v.CreatedAt = now
	v.UpdatedAt = now
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO saved_views (id, user, name, filters, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		v.ID, v.User, v.Name, string(data), v.CreatedAt, v.UpdatedAt,
	); err != nil {
		return fmt.Errorf("save view: %w", err)
	}
	return nil
}

// ListViews returns the saved views of a user.
func (s *Store) ListViews(ctx context.Context, user string) ([]*SavedView, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user, name, filters, created_at, updated_at FROM saved_views
		 WHERE user = ? ORDER BY name ASC`, user)
	if err != nil {
		return nil, fmt.Errorf("list saved views: %w", err)
	}
	defer rows.Close()

	var out []*SavedView
	for rows.Next() {
		v := &SavedView{}
		var filters string
		if err := rows.Scan(&v.ID, &v.User, &v.Name, &filters, &v.CreatedAt, &v.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan view: %w", err)
		}
		if err := json.Unmarshal([]byte(filters), &v.Filters); err != nil {
			v.Filters = map[string]string{}
		}
		if v.Filters == nil {
			v.Filters = map[string]string{}
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate views: %w", err)
	}
	return out, nil
}

// GetView retrieves a saved view.
func (s *Store) GetView(ctx context.Context, user, id string) (*SavedView, error) {
	var v SavedView
	var filters string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user, name, filters, created_at, updated_at FROM saved_views WHERE user = ? AND id = ?`,
		user, id,
	).Scan(&v.ID, &v.User, &v.Name, &filters, &v.CreatedAt, &v.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("saved view %s not found", id)
	}
	if err != nil {
		return nil, fmt.Errorf("get view: %w", err)
	}
	if err := json.Unmarshal([]byte(filters), &v.Filters); err != nil {
		v.Filters = map[string]string{}
	}
	return &v, nil
}

// DeleteView removes a saved view.
func (s *Store) DeleteView(ctx context.Context, user, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM saved_views WHERE user = ? AND id = ?`, user, id)
	if err != nil {
		return fmt.Errorf("delete view: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("saved view %s not found", id)
	}
	return nil
}
