// Package assets implements the asset inventory: first-class security
// objects (hosts, servers, containers, cloud resources, ...) carrying
// criticality, ownership and exposure context.
//
// Design: docs/telemetry-coverage.md §2. Observed assets are created as
// drafts (created_by='observed', tagged "draft") and never influence
// scoring until an analyst confirms criticality.
package assets

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Entity types an asset can represent.
var EntityTypes = []string{
	"host", "server", "workstation", "container", "cloud_resource",
	"database", "application", "identity_provider", "network",
}

// Criticality levels.
var Criticalities = []string{"critical", "high", "medium", "low"}

// exploitAvailability values for asset_vulnerabilities.
var ExploitAvailability = []string{"in-the-wild", "public-poc", "theoretical", "unknown"}

// Asset is one inventory entry.
type Asset struct {
	ID                 string    `json:"id"`
	EntityType         string    `json:"entity_type"`
	EntityRef          string    `json:"entity_ref"`
	Name               string    `json:"name"`
	OS                 string    `json:"os,omitempty"`
	OSVersion          string    `json:"os_version,omitempty"`
	Environment        string    `json:"environment,omitempty"`
	Criticality        string    `json:"criticality"`
	Owner              string    `json:"owner,omitempty"`
	BusinessUnit       string    `json:"business_unit,omitempty"`
	Location           string    `json:"location,omitempty"`
	DataClassification string    `json:"data_classification,omitempty"`
	InternetExposed    bool      `json:"internet_exposed"`
	Tags               []string  `json:"tags,omitempty"`
	FirstSeen          time.Time `json:"first_seen"`
	LastSeen           time.Time `json:"last_seen"`
	CreatedBy          string    `json:"created_by,omitempty"`
	UpdatedAt          time.Time `json:"updated_at"`

	// Aliases and Software are populated by Get, not by Create/Update.
	Aliases  []Alias    `json:"aliases,omitempty"`
	Software []Software `json:"software,omitempty"`
}

// Alias is an alternative identity of an asset (fqdn, ip, serial, ...).
type Alias struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Software is one observed/declared software component on an asset.
type Software struct {
	Name      string    `json:"name"`
	Vendor    string    `json:"vendor,omitempty"`
	Version   string    `json:"version,omitempty"`
	CPE       string    `json:"cpe,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Source    string    `json:"source,omitempty"`
}

// Vulnerability links a CVE to an asset with exploitation context.
type Vulnerability struct {
	CVE               string  `json:"cve"`
	Severity          string  `json:"severity,omitempty"`
	CVSS              *float64 `json:"cvss,omitempty"`
	EPSS              *float64 `json:"epss,omitempty"`
	ExploitAvailable  string  `json:"exploit_available,omitempty"`
	Evidence          string  `json:"evidence,omitempty"`
	FirstSeen         time.Time `json:"first_seen"`
	LastSeen          time.Time `json:"last_seen"`
}

// ErrInvalid is returned for validation failures.
type ErrInvalid struct{ Msg string }

func (e *ErrInvalid) Error() string { return e.Msg }

// IsInvalid reports whether err is a validation error.
func IsInvalid(err error) bool {
	var ei *ErrInvalid
	return errors.As(err, &ei)
}

// Validate checks the invariant fields of an asset.
func Validate(a *Asset) error {
	if a == nil {
		return &ErrInvalid{Msg: "nil asset"}
	}
	if !contains(EntityTypes, a.EntityType) {
		return &ErrInvalid{Msg: fmt.Sprintf("invalid entity_type %q", a.EntityType)}
	}
	if a.EntityRef == "" {
		return &ErrInvalid{Msg: "entity_ref is required"}
	}
	if strings.TrimSpace(a.Name) == "" {
		return &ErrInvalid{Msg: "name is required"}
	}
	if a.Criticality == "" {
		a.Criticality = "medium"
	}
	if !contains(Criticalities, a.Criticality) {
		return &ErrInvalid{Msg: fmt.Sprintf("invalid criticality %q", a.Criticality)}
	}
	return nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// SuggestCriticality proposes a criticality from naming conventions. The
// suggestion is advisory only: observed drafts store it as a tag and keep
// the medium default until an analyst confirms a level.
func SuggestCriticality(entityType, name, os string) string {
	n := strings.ToLower(name)
	switch {
	case entityType == "identity_provider",
		containsWord(n, "domain controller"), containsWord(n, "domain-controller"),
		containsWord(n, "payment"), containsWord(n, "card-"), containsWord(n, "core-banking"):
		return "critical"
	case entityType == "database",
		containsWord(n, "database"), containsWord(n, "db-"), containsWord(n, "pg-"),
		containsWord(n, "postgres"), containsWord(n, "mysql"), containsWord(n, "oracle"),
		containsWord(n, "sql"):
		return "high"
	case containsWord(n, "firewall"), containsWord(n, "router"), containsWord(n, "switch"),
		containsWord(n, "gateway"), containsWord(n, "loadbalancer"), containsWord(n, "load-balancer"),
		containsWord(n, "bastion"), containsWord(n, "jumpserver"):
		return "high"
	case entityType == "server":
		return "high"
	case containsWord(n, "ci-"), containsWord(n, "build"), containsWord(n, "test"),
		containsWord(n, "dev"), containsWord(n, "sandbox"), containsWord(n, "staging"),
		containsWord(n, "demo"), containsWord(n, "training"):
		return "low"
	}
	return "medium"
}

func containsWord(s, w string) bool {
	return strings.Contains(s, w)
}
