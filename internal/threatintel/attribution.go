package threatintel

import (
	"context"
	"fmt"
)

// ActorsOf lists the threat-actor names attributed to one indicator
// (bounded). Used by the AI context builder for attribution.
func (s *Store) ActorsOf(ctx context.Context, indicatorID string, limit int) ([]string, error) {
	if limit <= 0 || limit > 20 {
		limit = 5
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT a.name FROM actor_indicators ai
		 JOIN threat_actors a ON a.id = ai.actor_id
		 WHERE ai.indicator_id = ? ORDER BY a.name LIMIT ?`, indicatorID, limit)
	if err != nil {
		return nil, fmt.Errorf("query indicator actors: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// MalwareOf lists the malware-family names linked to one indicator (bounded).
func (s *Store) MalwareOf(ctx context.Context, indicatorID string, limit int) ([]string, error) {
	if limit <= 0 || limit > 20 {
		limit = 5
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT m.name FROM malware_indicators mi
		 JOIN malware_families m ON m.id = mi.malware_id
		 WHERE mi.indicator_id = ? ORDER BY m.name LIMIT ?`, indicatorID, limit)
	if err != nil {
		return nil, fmt.Errorf("query indicator malware: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}
