package assets

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

// Store persists the asset inventory.
type Store struct {
	db *sql.DB
}

// NewStore creates an asset store on the given database.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

// ErrNotFound is returned when an asset does not exist.
var ErrNotFound = errors.New("asset not found")

const assetColumns = `id, entity_type, entity_ref, name, os, os_version, environment,
	criticality, owner, business_unit, location, data_classification,
	internet_exposed, tags, first_seen, last_seen, created_by, updated_at`

func scanAsset(row interface{ Scan(...any) error }) (*Asset, error) {
	var (
		a           Asset
		exposed     int
		tags        string
		os, osVer   sql.NullString
		environment sql.NullString
		owner, bu   sql.NullString
		location    sql.NullString
		dataClass   sql.NullString
		createdBy   sql.NullString
	)
	err := row.Scan(
		&a.ID, &a.EntityType, &a.EntityRef, &a.Name,
		&os, &osVer, &environment,
		&a.Criticality, &owner, &bu, &location, &dataClass,
		&exposed, &tags, &a.FirstSeen, &a.LastSeen, &createdBy, &a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	a.OS = os.String
	a.OSVersion = osVer.String
	a.Environment = environment.String
	a.Owner = owner.String
	a.BusinessUnit = bu.String
	a.Location = location.String
	a.DataClassification = dataClass.String
	a.InternetExposed = exposed != 0
	a.CreatedBy = createdBy.String
	if tags != "" {
		_ = json.Unmarshal([]byte(tags), &a.Tags)
	}
	if a.Tags == nil {
		a.Tags = []string{}
	}
	return &a, nil
}

// Create inserts a new asset (analyst-created or via API).
func (s *Store) Create(ctx context.Context, a *Asset) (*Asset, error) {
	if err := Validate(a); err != nil {
		return nil, err
	}
	if a.Criticality == "" {
		a.Criticality = "medium"
	}
	now := time.Now().UTC()
	a.ID = "asset-" + uuid.NewString()
	if a.CreatedBy == "" {
		a.CreatedBy = "analyst"
	}
	if a.FirstSeen.IsZero() {
		a.FirstSeen = now
	}
	if a.LastSeen.IsZero() {
		a.LastSeen = a.FirstSeen
	}
	a.UpdatedAt = now

	tags, _ := json.Marshal(a.Tags)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO assets (`+assetColumns+`)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.EntityType, a.EntityRef, a.Name,
		a.OS, a.OSVersion, a.Environment,
		a.Criticality, a.Owner, a.BusinessUnit, a.Location, a.DataClassification,
		boolToInt(a.InternetExposed), string(tags), a.FirstSeen, a.LastSeen,
		a.CreatedBy, a.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, &ErrInvalid{Msg: fmt.Sprintf("asset already exists for entity_ref %q", a.EntityRef)}
		}
		return nil, fmt.Errorf("insert asset: %w", err)
	}
	return a, nil
}

// Observe is the observed-draft creation hook: the first event naming a
// host auto-creates a draft asset. Existing assets only have last_seen
// touched. Returns (asset, created).
//
// The suggested criticality is advisory only: it is stored as a tag and
// the draft keeps the medium default until an analyst confirms a level.
func (s *Store) Observe(ctx context.Context, entityType, entityRef, name, os string, at time.Time) (*Asset, bool, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	if ex, err := s.GetByRef(ctx, entityType, entityRef); err == nil && ex != nil {
		_, _ = s.db.ExecContext(ctx, `UPDATE assets SET last_seen = ? WHERE id = ?`, at, ex.ID)
		return ex, false, nil
	}
	suggested := SuggestCriticality(entityType, name, os)
	a := &Asset{
		EntityType:  entityType,
		EntityRef:   entityRef,
		Name:        name,
		OS:          os,
		Criticality: "medium",
		Tags:        []string{"draft", "criticality-suggested:" + suggested},
		FirstSeen:   at,
		LastSeen:    at,
		CreatedBy:   "observed",
	}
	created, err := s.Create(ctx, a)
	if err != nil {
		if IsInvalid(err) {
			// Lost the create race: someone else made it first.
			if ex, gerr := s.GetByRef(ctx, entityType, entityRef); gerr == nil {
				return ex, false, nil
			}
		}
		return nil, false, err
	}
	return created, true, nil
}

// Get returns one asset with its aliases and software.
func (s *Store) Get(ctx context.Context, id string) (*Asset, error) {
	if id == "" {
		return nil, ErrNotFound
	}
	row := s.db.QueryRowContext(ctx, `SELECT `+assetColumns+` FROM assets WHERE id = ?`, id)
	a, err := scanAsset(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get asset: %w", err)
	}
	if err := s.loadRelated(ctx, a); err != nil {
		return nil, err
	}
	return a, nil
}

// GetByRef returns the asset for an entity type+ref pair.
func (s *Store) GetByRef(ctx context.Context, entityType, entityRef string) (*Asset, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+assetColumns+` FROM assets WHERE entity_type = ? AND entity_ref = ?`, entityType, entityRef)
	a, err := scanAsset(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get asset by ref: %w", err)
	}
	if err := s.loadRelated(ctx, a); err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Store) loadRelated(ctx context.Context, a *Asset) error {
	rows, err := s.db.QueryContext(ctx, `SELECT alias_type, alias_value FROM asset_aliases WHERE asset_id = ? ORDER BY alias_type, alias_value`, a.ID)
	if err != nil {
		return fmt.Errorf("load aliases: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var al Alias
		if err := rows.Scan(&al.Type, &al.Value); err != nil {
			return err
		}
		a.Aliases = append(a.Aliases, al)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	rows, err = s.db.QueryContext(ctx, `SELECT name, vendor, version, cpe, first_seen, last_seen, source
		FROM asset_software WHERE asset_id = ? ORDER BY name`, a.ID)
	if err != nil {
		return fmt.Errorf("load software: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var sw Software
		var vendor, cpe, source sql.NullString
		if err := rows.Scan(&sw.Name, &vendor, &sw.Version, &cpe, &sw.FirstSeen, &sw.LastSeen, &source); err != nil {
			return err
		}
		sw.Vendor = vendor.String
		sw.CPE = cpe.String
		sw.Source = source.String
		a.Software = append(a.Software, sw)
	}
	return rows.Err()
}

// ListFilter filters the asset list.
type ListFilter struct {
	Q          string // case-insensitive name substring
	EntityType string
	Criticality string
	Limit      int
}

// List returns assets matching the filter (newest last_seen first).
func (s *Store) List(ctx context.Context, f ListFilter) ([]*Asset, int, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	conds := []string{"1=1"}
	args := []any{}
	if f.Q != "" {
		conds = append(conds, "name LIKE ? COLLATE NOCASE")
		args = append(args, "%"+f.Q+"%")
	}
	if f.EntityType != "" {
		conds = append(conds, "entity_type = ?")
		args = append(args, f.EntityType)
	}
	if f.Criticality != "" {
		conds = append(conds, "criticality = ?")
		args = append(args, f.Criticality)
	}
	where := strings.Join(conds, " AND ")

	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM assets WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count assets: %w", err)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+assetColumns+` FROM assets WHERE `+where+` ORDER BY last_seen DESC, name ASC LIMIT ?`,
		append(args, f.Limit)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list assets: %w", err)
	}
	defer rows.Close()
	out := make([]*Asset, 0, f.Limit)
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

// UpdateInput carries the mutable fields of a PATCH. nil fields are left
// untouched; a non-nil empty string clears the field.
type UpdateInput struct {
	Name               *string
	OS                 *string
	OSVersion          *string
	Environment        *string
	Criticality        *string
	Owner              *string
	BusinessUnit       *string
	Location           *string
	DataClassification *string
	InternetExposed    *bool
	Tags               *[]string
}

// Update applies a partial update to an asset.
func (s *Store) Update(ctx context.Context, id string, in UpdateInput) (*Asset, error) {
	a, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	sets := []string{}
	args := []any{}
	add := func(col string, val any) {
		sets = append(sets, col+" = ?")
		args = append(args, val)
	}
	if in.Name != nil {
		if strings.TrimSpace(*in.Name) == "" {
			return nil, &ErrInvalid{Msg: "name must not be empty"}
		}
		add("name", *in.Name)
	}
	if in.OS != nil {
		add("os", *in.OS)
	}
	if in.OSVersion != nil {
		add("os_version", *in.OSVersion)
	}
	if in.Environment != nil {
		add("environment", *in.Environment)
	}
	if in.Criticality != nil {
		if !contains(Criticalities, *in.Criticality) {
			return nil, &ErrInvalid{Msg: fmt.Sprintf("invalid criticality %q", *in.Criticality)}
		}
		sets = append(sets, "criticality = ?")
		args = append(args, *in.Criticality)
		// Confirming criticality by an analyst exits draft status: drop the
		// draft/suggestion tags unless the caller supplied explicit tags.
		if in.Tags == nil {
			cleaned := dedupTags(stripDraftTags(a.Tags))
			in.Tags = &cleaned
		}
	}
	if in.Owner != nil {
		add("owner", *in.Owner)
	}
	if in.BusinessUnit != nil {
		add("business_unit", *in.BusinessUnit)
	}
	if in.Location != nil {
		add("location", *in.Location)
	}
	if in.DataClassification != nil {
		add("data_classification", *in.DataClassification)
	}
	if in.InternetExposed != nil {
		sets = append(sets, "internet_exposed = ?")
		args = append(args, boolToInt(*in.InternetExposed))
	}
	if in.Tags != nil {
		tags, _ := json.Marshal(*in.Tags)
		sets = append(sets, "tags = ?")
		args = append(args, string(tags))
	}
	if len(sets) == 0 {
		return a, nil
	}
	sets = append(sets, "updated_at = ?")
	args = append(args, time.Now().UTC())
	args = append(args, id)
	if _, err := s.db.ExecContext(ctx, `UPDATE assets SET `+strings.Join(sets, ", ")+` WHERE id = ?`, args...); err != nil {
		return nil, fmt.Errorf("update asset: %w", err)
	}
	return s.Get(ctx, id)
}

// Delete removes an asset and its aliases/software/vulnerabilities.
func (s *Store) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM assets WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete asset: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AddAlias registers an alias for an asset.
func (s *Store) AddAlias(ctx context.Context, assetID, aliasType, value string) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO asset_aliases (asset_id, alias_type, alias_value) VALUES (?,?,?)`,
		assetID, aliasType, value); err != nil {
		return fmt.Errorf("add alias: %w", err)
	}
	return nil
}

// UpsertSoftware records an observed/declared software component.
func (s *Store) UpsertSoftware(ctx context.Context, assetID string, sw Software) error {
	if sw.FirstSeen.IsZero() {
		sw.FirstSeen = time.Now().UTC()
	}
	if sw.LastSeen.IsZero() {
		sw.LastSeen = sw.FirstSeen
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO asset_software (asset_id, name, vendor, version, cpe, first_seen, last_seen, source)
		VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(asset_id, name, version) DO UPDATE SET
			vendor = COALESCE(excluded.vendor, asset_software.vendor),
			cpe = COALESCE(excluded.cpe, asset_software.cpe),
			last_seen = excluded.last_seen,
			source = COALESCE(excluded.source, asset_software.source)`,
		assetID, sw.Name, nullStr(sw.Vendor), nullStr(sw.Version), nullStr(sw.CPE),
		sw.FirstSeen, sw.LastSeen, nullStr(sw.Source))
	if err != nil {
		return fmt.Errorf("upsert software: %w", err)
	}
	return nil
}

// UpsertVulnerability links a CVE to an asset.
func (s *Store) UpsertVulnerability(ctx context.Context, assetID string, v Vulnerability) error {
	if v.FirstSeen.IsZero() {
		v.FirstSeen = time.Now().UTC()
	}
	if v.LastSeen.IsZero() {
		v.LastSeen = v.FirstSeen
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO asset_vulnerabilities (asset_id, cve, severity, cvss, epss, exploit_available, evidence, first_seen, last_seen)
		VALUES (?,?,?,?,?,?,?,?,?)
		ON CONFLICT(asset_id, cve) DO UPDATE SET
			severity = COALESCE(excluded.severity, asset_vulnerabilities.severity),
			cvss = COALESCE(excluded.cvss, asset_vulnerabilities.cvss),
			epss = COALESCE(excluded.epss, asset_vulnerabilities.epss),
			exploit_available = COALESCE(excluded.exploit_available, asset_vulnerabilities.exploit_available),
			evidence = COALESCE(excluded.evidence, asset_vulnerabilities.evidence),
			last_seen = excluded.last_seen`,
		assetID, v.CVE, nullStr(v.Severity), v.CVSS, v.EPSS, nullStr(v.ExploitAvailable),
		nullStr(v.Evidence), v.FirstSeen, v.LastSeen)
	if err != nil {
		return fmt.Errorf("upsert vulnerability: %w", err)
	}
	return nil
}

// Vulnerabilities lists the CVEs linked to an asset.
func (s *Store) Vulnerabilities(ctx context.Context, assetID string) ([]Vulnerability, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT cve, severity, cvss, epss, exploit_available, evidence, first_seen, last_seen
		FROM asset_vulnerabilities WHERE asset_id = ? ORDER BY last_seen DESC`, assetID)
	if err != nil {
		return nil, fmt.Errorf("list vulnerabilities: %w", err)
	}
	defer rows.Close()
	out := []Vulnerability{}
	for rows.Next() {
		var v Vulnerability
		var severity, exploit, evidence sql.NullString
		if err := rows.Scan(&v.CVE, &severity, &v.CVSS, &v.EPSS, &exploit, &evidence, &v.FirstSeen, &v.LastSeen); err != nil {
			return nil, err
		}
		v.Severity = severity.String
		v.ExploitAvailable = exploit.String
		v.Evidence = evidence.String
		out = append(out, v)
	}
	return out, rows.Err()
}

// Count returns the total number of assets.
func (s *Store) Count(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM assets`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count assets: %w", err)
	}
	return n, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// stripDraftTags removes lifecycle tags (draft + suggestions).
func stripDraftTags(tags []string) []string {
	out := tags[:0]
	for _, t := range tags {
		if t == "draft" || strings.HasPrefix(t, "criticality-suggested:") {
			continue
		}
		out = append(out, t)
	}
	return out
}

func dedupTags(tags []string) []string {
	seen := make(map[string]bool, len(tags))
	out := tags[:0]
	for _, t := range tags {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}
