package entities

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"quetzalog/pkg/event"
)

// Store persists entity v2 data (identities, meta, relationship meta).
type Store struct {
	db *sql.DB
}

// NewStore creates an entity v2 store.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

// UpsertIdentity inserts or promotes an alias -> canonical link.
// Promotions are monotonic in evidence: a weaker status never demotes a
// stronger one, and confidence only moves up.
func (s *Store) UpsertIdentity(ctx context.Context, in Identity) error {
	if in.Status == "" {
		in.Status = "unknown"
	}
	if in.Confidence <= 0 {
		in.Confidence = 0.5
	}
	if in.Source == "" {
		in.Source = "observation"
	}
	now := time.Now().UTC()
	if in.FirstSeen.IsZero() {
		in.FirstSeen = now
	}
	if in.LastSeen.IsZero() {
		in.LastSeen = in.FirstSeen
	}
	if in.ID == "" {
		in.ID = event.GenerateEventID()
	}

	var curStatus string
	var curConf float64
	err := s.db.QueryRowContext(ctx, `
		SELECT status, confidence FROM entity_identities
		WHERE canonical_type = ? AND canonical_value = ? AND alias_type = ? AND alias_value = ?`,
		in.CanonicalType, in.CanonicalValue, in.AliasType, in.AliasValue).Scan(&curStatus, &curConf)
	if err == nil {
		if !IdentityStatusBetter(in.Status, curStatus) {
			in.Status = curStatus
		}
		if in.Confidence < curConf {
			in.Confidence = curConf
		}
	} else if err != sql.ErrNoRows {
		return fmt.Errorf("lookup identity: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO entity_identities (id, canonical_type, canonical_value, alias_type, alias_value,
			status, confidence, source, first_seen, last_seen)
		VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(canonical_type, canonical_value, alias_type, alias_value) DO UPDATE SET
			status = excluded.status,
			confidence = excluded.confidence,
			last_seen = excluded.last_seen`,
		in.ID, in.CanonicalType, in.CanonicalValue, in.AliasType, in.AliasValue,
		in.Status, in.Confidence, in.Source, in.FirstSeen, in.LastSeen,
	)
	if err != nil {
		return fmt.Errorf("upsert identity: %w", err)
	}
	return nil
}

// IdentitiesFor returns all aliases of a canonical entity.
func (s *Store) IdentitiesFor(ctx context.Context, canonicalType, canonicalValue string) ([]Identity, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, canonical_type, canonical_value, alias_type, alias_value,
			status, confidence, source, first_seen, last_seen
		FROM entity_identities WHERE canonical_type = ? AND canonical_value = ?
		ORDER BY status DESC, confidence DESC`, canonicalType, canonicalValue)
	if err != nil {
		return nil, fmt.Errorf("query identities: %w", err)
	}
	defer rows.Close()
	out := []Identity{}
	for rows.Next() {
		var id Identity
		if err := rows.Scan(&id.ID, &id.CanonicalType, &id.CanonicalValue, &id.AliasType,
			&id.AliasValue, &id.Status, &id.Confidence, &id.Source, &id.FirstSeen, &id.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Link records an analyst-confirmed alias (status confirmed, confidence 1.0,
// source analyst).
func (s *Store) Link(ctx context.Context, canonicalType, canonicalValue, aliasType, aliasValue string) error {
	return s.UpsertIdentity(ctx, Identity{
		CanonicalType:  canonicalType,
		CanonicalValue: canonicalValue,
		AliasType:      aliasType,
		AliasValue:     aliasValue,
		Status:         "confirmed",
		Confidence:     1.0,
		Source:         "analyst",
	})
}

// Unlink removes an alias row (analyst reversal; independent entities remain).
func (s *Store) Unlink(ctx context.Context, canonicalType, canonicalValue, aliasType, aliasValue string) error {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM entity_identities
		WHERE canonical_type = ? AND canonical_value = ? AND alias_type = ? AND alias_value = ?`,
		canonicalType, canonicalValue, aliasType, aliasValue)
	if err != nil {
		return fmt.Errorf("unlink identity: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("identity not found")
	}
	return nil
}

// Resolve finds entity candidates for a raw string: direct value matches in
// any type, plus alias-table hits that point at a canonical entity.
func (s *Store) Resolve(ctx context.Context, raw string) ([]Candidate, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	out := []Candidate{}
	seen := map[string]bool{}

	rows, err := s.db.QueryContext(ctx, `
		SELECT type, value, count, first_seen, last_seen FROM entities WHERE value = ?`, raw)
	if err != nil {
		return nil, fmt.Errorf("resolve values: %w", err)
	}
	for rows.Next() {
		var c Candidate
		var firstSeen, lastSeen time.Time
		if err := rows.Scan(&c.Type, &c.Value, &c.Count, &firstSeen, &lastSeen); err != nil {
			_ = rows.Close()
			return nil, err
		}
		c.MatchedAs = "value"
		c.Confidence = 1.0
		c.FirstSeen = firstSeen.Format(time.RFC3339)
		c.LastSeen = lastSeen.Format(time.RFC3339)
		if !seen[c.Type+":"+c.Value] {
			out = append(out, c)
			seen[c.Type+":"+c.Value] = true
		}
	}
	_ = rows.Close()

	rows, err = s.db.QueryContext(ctx, `
		SELECT canonical_type, canonical_value, status, confidence
		FROM entity_identities WHERE alias_value = ? AND status IN ('confirmed','probable')
		ORDER BY status DESC, confidence DESC`, raw)
	if err != nil {
		return nil, fmt.Errorf("resolve aliases: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			ct, cv, status string
			cred           float64
		)
		if err := rows.Scan(&ct, &cv, &status, &cred); err != nil {
			return nil, err
		}
		if seen[ct+":"+cv] {
			continue
		}
		out = append(out, Candidate{
			Type:       ct,
			Value:      cv,
			MatchedAs:  "alias",
			Status:     status,
			Confidence: cred,
		})
		seen[ct+":"+cv] = true
	}
	return out, rows.Err()
}

// UpsertMeta merges metadata for an entity (unspecified fields keep their
// stored values).
func (s *Store) UpsertMeta(ctx context.Context, m Meta) error {
	if m.UpdatedAt.IsZero() {
		m.UpdatedAt = time.Now().UTC()
	}
	var tags string
	if m.Tags != nil {
		b, _ := json.Marshal(m.Tags)
		tags = string(b)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO entity_meta (type, value, display_name, os, os_version, environment,
			internet_exposed, privilege, cloud_provider, cloud_account, tags, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(type, value) DO UPDATE SET
			display_name = COALESCE(NULLIF(excluded.display_name,''), entity_meta.display_name),
			os = COALESCE(NULLIF(excluded.os,''), entity_meta.os),
			os_version = COALESCE(NULLIF(excluded.os_version,''), entity_meta.os_version),
			environment = COALESCE(NULLIF(excluded.environment,''), entity_meta.environment),
			internet_exposed = COALESCE(excluded.internet_exposed, entity_meta.internet_exposed),
			privilege = COALESCE(NULLIF(excluded.privilege,''), entity_meta.privilege),
			cloud_provider = COALESCE(NULLIF(excluded.cloud_provider,''), entity_meta.cloud_provider),
			cloud_account = COALESCE(NULLIF(excluded.cloud_account,''), entity_meta.cloud_account),
			tags = COALESCE(NULLIF(excluded.tags,''), entity_meta.tags),
			updated_at = excluded.updated_at`,
		m.Type, m.Value, nullStr(m.DisplayName), nullStr(m.OS), nullStr(m.OSVersion),
		nullStr(m.Environment), m.InternetExposed, nullStr(m.Privilege),
		nullStr(m.CloudProvider), nullStr(m.CloudAccount), nullStr(tags), m.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("upsert meta: %w", err)
	}
	return nil
}

// GetMeta returns the metadata for one entity (nil when absent).
func (s *Store) GetMeta(ctx context.Context, entityType, value string) (*Meta, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT type, value, display_name, os, os_version, environment, internet_exposed,
			privilege, cloud_provider, cloud_account, tags, updated_at
		FROM entity_meta WHERE type = ? AND value = ?`, entityType, value)
	var (
		m           Meta
		displayName sql.NullString
		os, osV     sql.NullString
		env         sql.NullString
		exposed     sql.NullInt64
		priv, cp, ca, tags sql.NullString
	)
	err := row.Scan(&m.Type, &m.Value, &displayName, &os, &osV, &env, &exposed,
		&priv, &cp, &ca, &tags, &m.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get meta: %w", err)
	}
	m.DisplayName = displayName.String
	applyMetaNulls(&m, os, osV, env, priv, cp, ca, tags, exposed)
	return &m, nil
}

func applyMetaNulls(m *Meta, os, osV, env, priv, cp, ca, tags sql.NullString, exposed sql.NullInt64) {
	m.OS = os.String
	m.OSVersion = osV.String
	m.Environment = env.String
	if exposed.Valid {
		b := exposed.Int64 != 0
		m.InternetExposed = &b
	}
	m.Privilege = priv.String
	m.CloudProvider = cp.String
	m.CloudAccount = ca.String
	if tags.String != "" {
		_ = json.Unmarshal([]byte(tags.String), &m.Tags)
	}
}

// UpsertRelationshipMeta records edge state + provenance.
func (s *Store) UpsertRelationshipMeta(ctx context.Context, rm RelationshipMeta) error {
	if rm.Status == "" {
		rm.Status = "observed"
	}
	if rm.SourceType == "" {
		rm.SourceType = "event"
	}
	now := time.Now().UTC()
	if rm.FirstSeen.IsZero() {
		rm.FirstSeen = now
	}
	if rm.LastSeen.IsZero() {
		rm.LastSeen = rm.FirstSeen
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO relationship_meta (from_type, from_value, to_type, to_value, relation,
			status, source_type, source_id, first_seen, last_seen, evidence)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(from_type, from_value, to_type, to_value, relation) DO UPDATE SET
			-- analyst rows win entirely; observed rows keep their state
			-- (an observed event does not flip an analyst-set state back)
			status = CASE WHEN excluded.source_type = 'analyst' THEN excluded.status
				ELSE relationship_meta.status END,
			source_type = CASE WHEN excluded.source_type = 'analyst' THEN excluded.source_type
				ELSE relationship_meta.source_type END,
			source_id = CASE WHEN excluded.source_type = 'analyst' THEN excluded.source_id
				ELSE relationship_meta.source_id END,
			last_seen = excluded.last_seen,
			evidence = COALESCE(NULLIF(excluded.evidence,''), relationship_meta.evidence)`,
		rm.FromType, rm.FromValue, rm.ToType, rm.ToValue, rm.Relation,
		rm.Status, rm.SourceType, nullStr(rm.SourceID), rm.FirstSeen, rm.LastSeen, nullStr(rm.Evidence),
	)
	if err != nil {
		return fmt.Errorf("upsert relationship meta: %w", err)
	}
	return nil
}

// RelationshipsOf returns all edges touching the entity (both directions),
// merged with relationship_meta when present.
func (s *Store) RelationshipsOf(ctx context.Context, entityType, value string, limit int) ([]Edge, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	// m.last_seen / r.created_at are selected separately (a SQL-level
	// COALESCE would strip the declared DATETIME type and the driver would
	// hand back a raw string); the coalescing happens below.
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.from_type, r.from_value, r.to_type, r.to_value, r.relation, r.weight,
			COALESCE(m.status, 'observed'), m.source_type, m.source_id,
			m.last_seen, r.created_at, m.evidence
		FROM relationships r
		LEFT JOIN relationship_meta m ON (
			m.from_type = r.from_type AND m.from_value = r.from_value
			AND m.to_type = r.to_type AND m.to_value = r.to_value
			AND m.relation = r.relation)
		WHERE ((r.from_type = ? AND r.from_value = ?)
			OR (r.to_type = ? AND r.to_value = ?))
		ORDER BY r.created_at DESC LIMIT ?`,
		entityType, value, entityType, value, limit)
	if err != nil {
		return nil, fmt.Errorf("query edges: %w", err)
	}
	defer rows.Close()
	out := []Edge{}
	for rows.Next() {
		var e Edge
		var srcType sql.NullString
		var srcID sql.NullString
		var metaSeen, edgeSeen sql.NullTime
		var evidence sql.NullString
		if err := rows.Scan(&e.FromType, &e.FromValue, &e.ToType, &e.ToValue, &e.Relation,
			&e.Weight, &e.Status, &srcType, &srcID, &metaSeen, &edgeSeen, &evidence); err != nil {
			return nil, err
		}
		e.SourceType = srcType.String
		e.SourceID = srcID.String
		if metaSeen.Valid {
			e.LastSeen = metaSeen.Time.Format(time.RFC3339)
		} else if edgeSeen.Valid {
			e.LastSeen = edgeSeen.Time.Format(time.RFC3339)
		}
		e.Evidence = evidence.String
		out = append(out, e)
	}
	return out, rows.Err()
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
