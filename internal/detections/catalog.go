package detections

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed catalog/*.yaml
var catalogFS embed.FS

// CatalogEntry is one versioned detection or hunting bundle in the seed
// catalog (spec §41/§54). Catalog entries are data, not code: they install
// as ordinary detection rules, visible/editable/disable-able like any other.
type CatalogEntry struct {
	Name        string        `yaml:"name" json:"name"`
	Title       string        `yaml:"title" json:"title"`
	Category    string        `yaml:"category" json:"category"` // detection | hunting
	Version     int           `yaml:"version" json:"version"`
	Severity    string        `yaml:"severity" json:"severity"`
	Description string        `yaml:"description" json:"description"`
	Hunting     bool          `yaml:"hunting" json:"hunting"`
	Tags        []string      `yaml:"tags,omitempty" json:"tags,omitempty"`
	Mitre       CatalogMitre  `yaml:"mitre,omitempty" json:"mitre,omitempty"`
	DataSources []string      `yaml:"data_sources,omitempty" json:"data_sources,omitempty"`
	FPNotes     string        `yaml:"fp_notes,omitempty" json:"fp_notes,omitempty"`
	References  []string      `yaml:"references,omitempty" json:"references,omitempty"`
	Rule        CatalogRule   `yaml:"rule" json:"rule"`
	TestEvents  []string      `yaml:"test_events,omitempty" json:"test_events,omitempty"`
}

// CatalogMitre carries the MITRE mapping for a catalog entry.
type CatalogMitre struct {
	Tactics    []string `yaml:"tactics,omitempty" json:"tactics,omitempty"`
	Techniques []string `yaml:"techniques,omitempty" json:"techniques,omitempty"`
}

// CatalogRule is the detection rule payload of a catalog entry.
type CatalogRule struct {
	Kind      string     `yaml:"kind" json:"kind"`
	Query     string     `yaml:"query" json:"query"`
	Threshold *Threshold `yaml:"threshold,omitempty" json:"threshold,omitempty"`
	GroupBy   []string   `yaml:"group_by,omitempty" json:"group_by,omitempty"`
}

// ListCatalog returns every catalog entry, sorted by name.
func ListCatalog() ([]CatalogEntry, error) {
	entries, err := catalogFS.ReadDir("catalog")
	if err != nil {
		return nil, fmt.Errorf("read catalog dir: %w", err)
	}
	out := []CatalogEntry{}
	for _, f := range entries {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".yaml") {
			continue
		}
		data, err := catalogFS.ReadFile("catalog/" + f.Name())
		if err != nil {
			return nil, fmt.Errorf("read catalog %s: %w", f.Name(), err)
		}
		var e CatalogEntry
		if err := yaml.Unmarshal(data, &e); err != nil {
			return nil, fmt.Errorf("parse catalog %s: %w", f.Name(), err)
		}
		if e.Name == "" {
			e.Name = strings.TrimSuffix(f.Name(), ".yaml")
		}
		if e.Version <= 0 {
			e.Version = 1
		}
		if e.Category == "" {
			if e.Hunting {
				e.Category = "hunting"
			} else {
				e.Category = "detection"
			}
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// CatalogEntryByName looks up one entry by its catalog name.
func CatalogEntryByName(name string) (*CatalogEntry, error) {
	entries, err := ListCatalog()
	if err != nil {
		return nil, err
	}
	for i := range entries {
		if entries[i].Name == name {
			return &entries[i], nil
		}
	}
	return nil, fmt.Errorf("catalog entry %q not found", name)
}

// ToRule converts a catalog entry into the detection rule it installs as.
func (e *CatalogEntry) ToRule() *DetectionRule {
	kind := strings.TrimSpace(e.Rule.Kind)
	if kind == "" {
		kind = "spl"
	}
	tags := append([]string{}, e.Tags...)
	tags = append(tags, "catalog:"+e.Name)

	rule := &DetectionRule{
		Name:               e.Title,
		Description:        e.Description,
		Severity:           e.Severity,
		Kind:               kind,
		Query:              e.Rule.Query,
		Threshold:          e.Rule.Threshold,
		GroupBy:            e.Rule.GroupBy,
		Enabled:            true,
		Version:            e.Version,
		DataSources:        e.DataSources,
		FalsePositiveNotes: e.FPNotes,
		References:         e.References,
		Tags:               tags,
		TestEvents:         e.TestEvents,
	}
	if len(e.Mitre.Tactics) > 0 {
		rule.MITRETactic = e.Mitre.Tactics[0]
		rule.TacticIDs = e.Mitre.Tactics
	}
	if len(e.Mitre.Techniques) > 0 {
		rule.MITRETechnique = e.Mitre.Techniques[0]
		rule.MITRETechniques = e.Mitre.Techniques
	}
	return rule
}

// InstallCatalog persists (or upgrades) one catalog entry as a detection
// rule. The catalog version is stamped on install so upgrades are
// detectable. An existing rule with the same name is updated in place; the
// analyst's suppression state and schedule are preserved (catalog upgrades
// never silently unsuppress a rule).
func (s *Store) InstallCatalog(ctx context.Context, e *CatalogEntry) (*DetectionRule, error) {
	if e == nil {
		return nil, fmt.Errorf("nil catalog entry")
	}
	rule := e.ToRule()

	existing, err := s.FindByName(ctx, e.Title)
	if err != nil {
		return nil, fmt.Errorf("find existing rule: %w", err)
	}
	if existing != nil {
		rule.ID = existing.ID
		// Preserve analyst state across catalog upgrades.
		rule.Suppressed = existing.Suppressed
		rule.SuppressedBy = existing.SuppressedBy
		rule.SuppressReason = existing.SuppressReason
		if existing.ScheduleSeconds > 0 {
			rule.ScheduleSeconds = existing.ScheduleSeconds
		}
		if existing.CreatedBy != "" {
			rule.CreatedBy = existing.CreatedBy
		}
		if err := s.Update(ctx, rule); err != nil {
			return nil, fmt.Errorf("upgrade catalog rule: %w", err)
		}
		return rule, nil
	}
	if err := s.Create(ctx, rule); err != nil {
		return nil, fmt.Errorf("install catalog rule: %w", err)
	}
	return rule, nil
}

// FindByName returns the rule with the given name, or nil.
func (s *Store) FindByName(ctx context.Context, name string) (*DetectionRule, error) {
	list, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range list {
		if r.Name == name {
			return r, nil
		}
	}
	return nil, nil
}
