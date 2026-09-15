package threatintel

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Store persists the indicator model.
type Store struct {
	db *sql.DB
}

// NewStore creates the store.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

// ListFilter filters indicator listings.
type ListFilter struct {
	Type    string
	Q       string
	Limit   int
}

// Upsert inserts or refreshes an indicator and its source provenance row.
// The aggregate confidence is corroborated across distinct sources: a
// single source is discounted (principle 6).
func (s *Store) Upsert(ctx context.Context, in InIndicator) (*Indicator, error) {
	if err := ValidateIndicator(in); err != nil {
		return nil, err
	}
	if in.Source == "" {
		in.Source = "analyst"
	}
	if in.Confidence == 0 {
		in.Confidence = 0.5
	}
	if in.Reliability == 0 {
		in.Reliability = 0.8
	}
	norm := Normalize(in.Type, in.Value)
	now := time.Now().UTC()

	var id string
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM indicators WHERE type = ? AND normalized_value = ?`, in.Type, norm,
	).Scan(&id)
	switch err {
	case sql.ErrNoRows:
		id = "ioc-" + uuid.NewString()
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO indicators (id, type, value, normalized_value, severity, description, source, confidence, first_seen, last_seen)
			 VALUES (?,?,?,?,?,?,?,?,?,?)`,
			id, in.Type, in.Value, norm, in.Severity, nullableStr(in.Description), in.Source, in.Confidence, now, now); err != nil {
			return nil, fmt.Errorf("insert indicator: %w", err)
		}
	case nil:
		if _, err := s.db.ExecContext(ctx,
			`UPDATE indicators SET last_seen = ?, severity = ?, description = COALESCE(NULLIF(?, ''), description)
			 WHERE id = ?`, now, in.Severity, in.Description, id); err != nil {
			return nil, fmt.Errorf("update indicator: %w", err)
		}
	default:
		return nil, err
	}

	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO indicator_sources (indicator_id, source, source_url, reliability, confidence, first_seen, last_seen)
		 VALUES (?,?,?,?,?,?,?)
		 ON CONFLICT(indicator_id, source) DO UPDATE SET
			source_url = COALESCE(NULLIF(excluded.source_url, ''), indicator_sources.source_url),
			reliability = excluded.reliability,
			confidence = excluded.confidence,
			last_seen = excluded.last_seen`,
		id, in.Source, nullableStr(in.SourceURL), in.Reliability, in.Confidence, now, now); err != nil {
		return nil, fmt.Errorf("upsert indicator source: %w", err)
	}

	if in.Actor != "" {
		actorID, err := s.upsertActorByName(ctx, in.Actor, now)
		if err != nil {
			return nil, err
		}
		if _, err := s.db.ExecContext(ctx,
			`INSERT OR IGNORE INTO actor_indicators (actor_id, indicator_id, attribution) VALUES (?, ?, 'associated')`,
			actorID, id); err != nil {
			return nil, fmt.Errorf("link actor indicator: %w", err)
		}
	}

	if err := s.refreshConfidence(ctx, id); err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

// refreshConfidence recomputes the aggregate: the best per-source
// effective score (confidence × reliability), corroborated (max) when two
// or more distinct sources report it, discounted by 20% when it rests on
// a single source — one weak feed cannot classify an indicator.
func (s *Store) refreshConfidence(ctx context.Context, indicatorID string) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT confidence * reliability FROM indicator_sources WHERE indicator_id = ?`, indicatorID)
	if err != nil {
		return fmt.Errorf("query indicator sources: %w", err)
	}
	defer rows.Close()
	var best, second float64
	var n int
	for rows.Next() {
		var eff float64
		if err := rows.Scan(&eff); err != nil {
			return err
		}
		n++
		if eff > best {
			best = eff
		} else if eff > second {
			second = eff
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	agg := best
	if n == 1 {
		agg = best * 0.8
	}
	// Two sources with divergent scores: keep the corroborated best but
	// note it is not unanimous. (Full 5-dim confidence lands with the
	// correlation engine; this is the explainable v1 aggregate.)
	_ = second
	if _, err := s.db.ExecContext(ctx,
		`UPDATE indicators SET confidence = ? WHERE id = ?`, round3(agg), indicatorID); err != nil {
		return fmt.Errorf("refresh confidence: %w", err)
	}
	return nil
}

// Get loads one indicator.
func (s *Store) Get(ctx context.Context, id string) (*Indicator, error) {
	var i Indicator
	var desc sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, type, value, normalized_value, severity, description, source, confidence,
		        first_seen, last_seen, hit_count
		 FROM indicators WHERE id = ?`, id).
		Scan(&i.ID, &i.Type, &i.Value, &i.NormalizedValue, &i.Severity, &desc, &i.Source,
			&i.Confidence, &i.FirstSeen, &i.LastSeen, &i.HitCount)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get indicator: %w", err)
	}
	i.Description = desc.String
	return &i, nil
}

// ErrNotFound indicates a missing record.
var ErrNotFound = fmt.Errorf("not found")

// Lookup finds indicators whose value (raw or normalized) matches.
func (s *Store) Lookup(ctx context.Context, value string) ([]Indicator, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, type, value, normalized_value, severity, description, source, confidence,
		        first_seen, last_seen, hit_count
		 FROM indicators WHERE value = ? OR LOWER(value) = LOWER(?) OR normalized_value = LOWER(?)
		 ORDER BY confidence DESC LIMIT 50`, value, value, value)
	if err != nil {
		return nil, fmt.Errorf("lookup indicators: %w", err)
	}
	defer rows.Close()
	return scanIndicators(rows)
}

// LookupByType finds indicators of one type by raw or normalized value.
func (s *Store) LookupByType(ctx context.Context, typ, value string) ([]Indicator, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, type, value, normalized_value, severity, description, source, confidence,
		        first_seen, last_seen, hit_count
		 FROM indicators WHERE type = ? AND (value = ? OR LOWER(value) = LOWER(?) OR normalized_value = LOWER(?))
		 ORDER BY confidence DESC LIMIT 50`, typ, value, value, value)
	if err != nil {
		return nil, fmt.Errorf("lookup indicators by type: %w", err)
	}
	defer rows.Close()
	return scanIndicators(rows)
}

// List returns indicators by filter, newest first.
func (s *Store) List(ctx context.Context, f ListFilter) ([]Indicator, int, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	where := []string{"1=1"}
	args := []any{}
	if f.Type != "" {
		where = append(where, "type = ?")
		args = append(args, f.Type)
	}
	if f.Q != "" {
		where = append(where, "(value LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\')")
		args = append(args, escapeLike(f.Q), escapeLike(f.Q))
	}
	q := `SELECT COUNT(*) FROM indicators WHERE ` + strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, q, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count indicators: %w", err)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, type, value, normalized_value, severity, description, source, confidence,
		        first_seen, last_seen, hit_count
		 FROM indicators WHERE `+strings.Join(where, " AND ")+`
		 ORDER BY last_seen DESC LIMIT ?`, append(args, f.Limit)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list indicators: %w", err)
	}
	defer rows.Close()
	list, err := scanIndicators(rows)
	if err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

func scanIndicators(rows *sql.Rows) ([]Indicator, error) {
	var out []Indicator
	for rows.Next() {
		var i Indicator
		var desc sql.NullString
		if err := rows.Scan(&i.ID, &i.Type, &i.Value, &i.NormalizedValue, &i.Severity, &desc,
			&i.Source, &i.Confidence, &i.FirstSeen, &i.LastSeen, &i.HitCount); err != nil {
			return nil, err
		}
		i.Description = desc.String
		out = append(out, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// RecordHits increments hit counters and records observed co-occurrence
// when one event matches multiple indicators.
func (s *Store) RecordHits(ctx context.Context, ids []string, eventID string) error {
	now := time.Now().UTC()
	for i, id := range ids {
		if _, err := s.db.ExecContext(ctx,
			`UPDATE indicators SET hit_count = hit_count + 1, last_seen = ? WHERE id = ?`, now, id); err != nil {
			return fmt.Errorf("record hit: %w", err)
		}
		if i > 0 && eventID != "" {
			// Canonical pair order keeps (from,to) unique.
			a, b := ids[0], id
			if a > b {
				a, b = b, a
			}
			if _, err := s.db.ExecContext(ctx,
				`INSERT OR IGNORE INTO indicator_correlations (from_id, to_id, event_id, observed_at)
				 VALUES (?,?,?,?)`, a, b, eventID, now); err != nil {
				return fmt.Errorf("record correlation: %w", err)
			}
		}
	}
	return nil
}

// CorrelatedIDs returns the indicator IDs that co-occurred with the given
// one (most recent first).
func (s *Store) CorrelatedIDs(ctx context.Context, indicatorID string, limit int) ([]string, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT CASE WHEN from_id = ? THEN to_id ELSE from_id END
		 FROM indicator_correlations
		 WHERE from_id = ? OR to_id = ?
		 ORDER BY observed_at DESC LIMIT ?`, indicatorID, indicatorID, indicatorID, limit)
	if err != nil {
		return nil, fmt.Errorf("query correlations: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// SourcesOf returns the provenance rows for an indicator.
func (s *Store) SourcesOf(ctx context.Context, indicatorID string) ([]SourceRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT indicator_id, source, source_url, reliability, confidence, first_seen, last_seen
		 FROM indicator_sources WHERE indicator_id = ? ORDER BY source`, indicatorID)
	if err != nil {
		return nil, fmt.Errorf("query sources: %w", err)
	}
	defer rows.Close()
	var out []SourceRow
	for rows.Next() {
		var r SourceRow
		var url sql.NullString
		if err := rows.Scan(&r.IndicatorID, &r.Source, &url, &r.Reliability, &r.Confidence, &r.FirstSeen, &r.LastSeen); err != nil {
			return nil, err
		}
		r.SourceURL = url.String
		out = append(out, r)
	}
	return out, rows.Err()
}

// upsertActorByName creates or returns the actor ID for a name.
func (s *Store) upsertActorByName(ctx context.Context, name string, now time.Time) (string, error) {
	name = strings.TrimSpace(name)
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM threat_actors WHERE name = ?`, name).Scan(&id)
	switch err {
	case sql.ErrNoRows:
		id = "actor-" + uuid.NewString()
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO threat_actors (id, name, first_seen, last_seen) VALUES (?,?,?,?)`,
			id, name, now, now); err != nil {
			return "", fmt.Errorf("insert actor: %w", err)
		}
	case nil:
		if _, err := s.db.ExecContext(ctx,
			`UPDATE threat_actors SET last_seen = ? WHERE id = ?`, now, id); err != nil {
			return "", fmt.Errorf("touch actor: %w", err)
		}
	default:
		return "", err
	}
	return id, nil
}

// UpsertActor creates or updates a threat actor.
func (s *Store) UpsertActor(ctx context.Context, a Actor) (*Actor, error) {
	if strings.TrimSpace(a.Name) == "" {
		return nil, fmt.Errorf("actor name is required")
	}
	now := time.Now().UTC()
	id := a.ID
	if id == "" {
		id = "actor-" + uuid.NewString()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO threat_actors (id, name, aka, type, country, motivation, description, first_seen, last_seen)
		 VALUES (?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
			aka = excluded.aka, type = excluded.type, country = excluded.country,
			motivation = excluded.motivation, description = excluded.description,
			last_seen = excluded.last_seen`,
		id, a.Name, nullableStr(a.Aka), nullableStr(a.Type), nullableStr(a.Country),
		nullableStr(a.Motivation), nullableStr(a.Description), now, now)
	if err != nil {
		return nil, fmt.Errorf("upsert actor: %w", err)
	}
	return s.GetActor(ctx, id)
}

// GetActor loads an actor with its indicators.
func (s *Store) GetActor(ctx context.Context, id string) (*Actor, error) {
	var a Actor
	var aka, typ, country, mot, desc sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, aka, type, country, motivation, description, first_seen, last_seen
		 FROM threat_actors WHERE id = ?`, id).
		Scan(&a.ID, &a.Name, &aka, &typ, &country, &mot, &desc, &a.FirstSeen, &a.LastSeen)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get actor: %w", err)
	}
	a.Aka = aka.String
	a.Type = typ.String
	a.Country = country.String
	a.Motivation = mot.String
	a.Description = desc.String

	rows, err := s.db.QueryContext(ctx,
		`SELECT i.id, i.type, i.value, i.normalized_value, i.severity, i.description, i.source,
		        i.confidence, i.first_seen, i.last_seen, i.hit_count
		 FROM indicators i JOIN actor_indicators ai ON ai.indicator_id = i.id
		 WHERE ai.actor_id = ? ORDER BY i.last_seen DESC LIMIT 200`, id)
	if err != nil {
		return nil, fmt.Errorf("query actor indicators: %w", err)
	}
	defer rows.Close()
	list, err := scanIndicators(rows)
	if err != nil {
		return nil, err
	}
	a.Indicators = list
	return &a, nil
}

// ListActors returns all actors, newest first.
func (s *Store) ListActors(ctx context.Context, limit int) ([]Actor, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, aka, type, country, motivation, description, first_seen, last_seen
		 FROM threat_actors ORDER BY last_seen DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list actors: %w", err)
	}
	defer rows.Close()
	var out []Actor
	for rows.Next() {
		var a Actor
		var aka, typ, country, mot, desc sql.NullString
		if err := rows.Scan(&a.ID, &a.Name, &aka, &typ, &country, &mot, &desc, &a.FirstSeen, &a.LastSeen); err != nil {
			return nil, err
		}
		a.Aka = aka.String
		a.Type = typ.String
		a.Country = country.String
		a.Motivation = mot.String
		a.Description = desc.String
		out = append(out, a)
	}
	return out, rows.Err()
}

// UpsertCampaign creates or updates a campaign.
func (s *Store) UpsertCampaign(ctx context.Context, c Campaign) (*Campaign, error) {
	if strings.TrimSpace(c.Name) == "" {
		return nil, fmt.Errorf("campaign name is required")
	}
	now := time.Now().UTC()
	id := c.ID
	if id == "" {
		id = "camp-" + uuid.NewString()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO campaigns (id, name, actor_id, description, first_seen, last_seen)
		 VALUES (?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
			actor_id = excluded.actor_id, description = excluded.description,
			last_seen = excluded.last_seen`,
		id, c.Name, nullableStr(c.ActorID), nullableStr(c.Description), now, now)
	if err != nil {
		return nil, fmt.Errorf("upsert campaign: %w", err)
	}
	var out Campaign
	var actor, desc sql.NullString
	err = s.db.QueryRowContext(ctx,
		`SELECT id, name, actor_id, description, first_seen, last_seen FROM campaigns WHERE id = ?`, id).
		Scan(&out.ID, &out.Name, &actor, &desc, &out.FirstSeen, &out.LastSeen)
	if err != nil {
		return nil, err
	}
	out.ActorID = actor.String
	out.Description = desc.String
	return &out, nil
}

// ListCampaigns returns campaigns, newest first.
func (s *Store) ListCampaigns(ctx context.Context, limit int) ([]Campaign, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, actor_id, description, first_seen, last_seen
		 FROM campaigns ORDER BY last_seen DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list campaigns: %w", err)
	}
	defer rows.Close()
	var out []Campaign
	for rows.Next() {
		var c Campaign
		var actor, desc sql.NullString
		if err := rows.Scan(&c.ID, &c.Name, &actor, &desc, &c.FirstSeen, &c.LastSeen); err != nil {
			return nil, err
		}
		c.ActorID = actor.String
		c.Description = desc.String
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpsertMalware creates or updates a malware family.
func (s *Store) UpsertMalware(ctx context.Context, m MalwareFamily) (*MalwareFamily, error) {
	if strings.TrimSpace(m.Family) == "" {
		return nil, fmt.Errorf("malware family is required")
	}
	now := time.Now().UTC()
	id := m.ID
	if id == "" {
		id = "mal-" + uuid.NewString()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO malware_families (id, family, description, first_seen, last_seen)
		 VALUES (?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
			description = excluded.description, last_seen = excluded.last_seen`,
		id, m.Family, nullableStr(m.Description), now, now)
	if err != nil {
		return nil, fmt.Errorf("upsert malware: %w", err)
	}
	var out MalwareFamily
	var desc sql.NullString
	err = s.db.QueryRowContext(ctx,
		`SELECT id, family, description, first_seen, last_seen FROM malware_families WHERE id = ?`, id).
		Scan(&out.ID, &out.Family, &desc, &out.FirstSeen, &out.LastSeen)
	if err != nil {
		return nil, err
	}
	out.Description = desc.String
	return &out, nil
}

// ListMalware returns malware families, newest first.
func (s *Store) ListMalware(ctx context.Context, limit int) ([]MalwareFamily, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, family, description, first_seen, last_seen
		 FROM malware_families ORDER BY last_seen DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list malware: %w", err)
	}
	defer rows.Close()
	var out []MalwareFamily
	for rows.Next() {
		var m MalwareFamily
		var desc sql.NullString
		if err := rows.Scan(&m.ID, &m.Family, &desc, &m.FirstSeen, &m.LastSeen); err != nil {
			return nil, err
		}
		m.Description = desc.String
		out = append(out, m)
	}
	return out, rows.Err()
}

// SetProviderState records a provider sync attempt.
func (s *Store) SetProviderState(ctx context.Context, p ProviderState) error {
	if p.LastSync.IsZero() {
		p.LastSync = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO ti_provider_state (provider, last_sync, last_status, last_error, indicator_count)
		 VALUES (?,?,?,?,?)
		 ON CONFLICT(provider) DO UPDATE SET
			last_sync = excluded.last_sync,
			last_status = excluded.last_status,
			last_error = excluded.last_error,
			indicator_count = excluded.indicator_count`,
		p.Provider, p.LastSync, p.LastStatus, nullableStr(p.LastError), p.IndicatorCount)
	if err != nil {
		return fmt.Errorf("set provider state: %w", err)
	}
	return nil
}

// ProviderStates returns all provider states.
func (s *Store) ProviderStates(ctx context.Context) ([]ProviderState, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT provider, last_sync, last_status, last_error, indicator_count
		 FROM ti_provider_state ORDER BY provider`)
	if err != nil {
		return nil, fmt.Errorf("query provider states: %w", err)
	}
	defer rows.Close()
	var out []ProviderState
	for rows.Next() {
		var p ProviderState
		var sync sql.NullTime
		var status, errText sql.NullString
		if err := rows.Scan(&p.Provider, &sync, &status, &errText, &p.IndicatorCount); err != nil {
			return nil, err
		}
		if sync.Valid {
			p.LastSync = sync.Time
		}
		p.LastStatus = status.String
		p.LastError = errText.String
		out = append(out, p)
	}
	return out, rows.Err()
}

func round3(f float64) float64 {
	return float64(int64(f*1000+0.5)) / 1000
}

func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return "%" + s + "%"
}

func nullableStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}


