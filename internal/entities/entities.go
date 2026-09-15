// Package entities implements entity resolution v2: alias -> canonical
// identity mapping with explicit status/confidence/source, rich per-entity
// metadata, and relationship provenance.
//
// Design: docs/entity-model.md. The hot-write 5-tuple tables
// (entities/relationships in internal/correlation) are untouched; all v2
// data lives in the 009 migrations. No aggressive merges: below-threshold
// links stay 'possible' and are not used for pivots until promoted.
package entities

import (
	"time"
)

// IdentityStatus ranks alias resolution strength.
var IdentityStatuses = []string{"unknown", "possible", "probable", "confirmed"}

var statusRank = map[string]int{
	"unknown":   0,
	"possible":  1,
	"probable":  2,
	"confirmed": 3,
}

// RankIdentity orders statuses from weakest to strongest.
func RankIdentity(s string) int {
	return statusRank[s]
}

// IdentityStatusBetter reports whether candidate beats current (monotonic
// promotion; equal ranks keep the current row).
func IdentityStatusBetter(candidate, current string) bool {
	return statusRank[candidate] > statusRank[current]
}

// Identity links an alias to a canonical entity.
type Identity struct {
	ID              string    `json:"id"`
	CanonicalType   string    `json:"canonical_type"`
	CanonicalValue  string    `json:"canonical_value"`
	AliasType       string    `json:"alias_type"`
	AliasValue      string    `json:"alias_value"`
	Status          string    `json:"status"`
	Confidence      float64   `json:"confidence"`
	Source          string    `json:"source"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
}

// Meta is rich per-entity metadata (assets live in their own table).
type Meta struct {
	Type            string   `json:"type"`
	Value           string   `json:"value"`
	DisplayName     string   `json:"display_name,omitempty"`
	OS              string   `json:"os,omitempty"`
	OSVersion       string   `json:"os_version,omitempty"`
	Environment     string   `json:"environment,omitempty"`
	InternetExposed *bool    `json:"internet_exposed,omitempty"`
	Privilege       string   `json:"privilege,omitempty"`
	CloudProvider   string   `json:"cloud_provider,omitempty"`
	CloudAccount    string   `json:"cloud_account,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// EdgeStatus is the state of a relationship-meta row.
var EdgeStatuses = []string{"observed", "inferred", "potential", "blocked"}

// RelationshipMeta carries state + provenance for a graph edge.
type RelationshipMeta struct {
	FromType   string    `json:"from_type"`
	FromValue  string    `json:"from_value"`
	ToType     string    `json:"to_type"`
	ToValue    string    `json:"to_value"`
	Relation   string    `json:"relation"`
	Status     string    `json:"status"`
	SourceType string    `json:"source_type"`
	SourceID   string    `json:"source_id,omitempty"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Evidence   string    `json:"evidence,omitempty"`
}

// Edge is a graph edge with its meta (if any).
type Edge struct {
	FromType   string `json:"from_type"`
	FromValue  string `json:"from_value"`
	ToType     string `json:"to_type"`
	ToValue    string `json:"to_value"`
	Relation   string `json:"relation"`
	Weight     int    `json:"weight"`
	Status     string `json:"status"`
	SourceType string `json:"source_type,omitempty"`
	SourceID   string `json:"source_id,omitempty"`
	LastSeen   string `json:"last_seen,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
}

// Candidate is one resolution result for a raw string.
type Candidate struct {
	Type        string  `json:"type"`
	Value       string  `json:"value"`
	MatchedAs   string  `json:"matched_as"` // "value" or "alias"
	Status      string  `json:"status"`     // "" when matched as a plain value
	Confidence  float64 `json:"confidence"`
	Count       int     `json:"count"`
	FirstSeen   string  `json:"first_seen"`
	LastSeen    string  `json:"last_seen"`
}
