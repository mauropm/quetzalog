package assets

import (
	"context"
	"strings"
	"testing"
	"time"

	"quetzalog/internal/database"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewStore(db)
}

func TestValidate(t *testing.T) {
	valid := &Asset{EntityType: "host", EntityRef: "host:h1", Name: "h1"}
	if err := Validate(valid); err != nil {
		t.Fatalf("valid asset rejected: %v", err)
	}
	if valid.Criticality != "medium" {
		t.Errorf("default criticality: %q", valid.Criticality)
	}
	if err := Validate(&Asset{EntityType: "mars-lander", EntityRef: "x", Name: "x"}); err == nil {
		t.Error("bad entity type accepted")
	}
	if err := Validate(&Asset{EntityType: "host", EntityRef: "", Name: "x"}); err == nil {
		t.Error("empty entity_ref accepted")
	}
	if err := Validate(&Asset{EntityType: "host", EntityRef: "host:x", Name: "  "}); err == nil {
		t.Error("empty name accepted")
	}
}

func TestCreateAndGet(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a, err := s.Create(ctx, &Asset{
		EntityType:      "server",
		EntityRef:       "host:FILE-SRV-01",
		Name:            "FILE-SRV-01",
		OS:              "linux",
		Owner:           "sre",
		Criticality:     "high",
		InternetExposed: true,
		Tags:            []string{"file-server"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !strings.HasPrefix(a.ID, "asset-") || a.CreatedBy != "analyst" {
		t.Errorf("id/created_by: %q %q", a.ID, a.CreatedBy)
	}
	// Duplicate entity_ref must be rejected.
	if _, err := s.Create(ctx, &Asset{EntityType: "server", EntityRef: "host:FILE-SRV-01", Name: "dup"}); !IsInvalid(err) {
		t.Errorf("duplicate create: %v", err)
	}

	got, err := s.Get(ctx, a.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "FILE-SRV-01" || got.Criticality != "high" || !got.InternetExposed {
		t.Errorf("roundtrip: %+v", got)
	}
	if len(got.Tags) != 1 || got.Tags[0] != "file-server" {
		t.Errorf("tags: %v", got.Tags)
	}

	if _, err := s.GetByRef(ctx, "server", "host:FILE-SRV-01"); err != nil {
		t.Errorf("get by ref: %v", err)
	}
	if _, err := s.GetByRef(ctx, "host", "host:FILE-SRV-01"); err != ErrNotFound {
		t.Errorf("get by ref wrong type: %v", err)
	}
	if _, err := s.Get(ctx, "asset-nope"); err != ErrNotFound {
		t.Errorf("missing asset: %v", err)
	}
}

func TestObserveDraftLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	created, isCreated, err := s.Observe(ctx, "host", "host:pg-01", "pg-01", "", now)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if !isCreated || created.CreatedBy != "observed" {
		t.Fatalf("first observe: created=%v by=%q", isCreated, created.CreatedBy)
	}
	if created.Criticality != "medium" {
		t.Errorf("draft criticality must stay medium: %q", created.Criticality)
	}
	draft, suggested := false, false
	for _, tag := range created.Tags {
		if tag == "draft" {
			draft = true
		}
		if tag == "criticality-suggested:high" {
			suggested = true
		}
	}
	if !draft || !suggested {
		t.Errorf("draft tags missing: %v", created.Tags)
	}

	// Second observe: touch only.
	_, isCreated, err = s.Observe(ctx, "host", "host:pg-01", "pg-01", "", now.Add(time.Hour))
	if err != nil || isCreated {
		t.Fatalf("second observe: created=%v err=%v", isCreated, err)
	}
	if ex, _ := s.GetByRef(ctx, "host", "host:pg-01"); ex != nil && ex.LastSeen != now.Add(time.Hour) {
		t.Errorf("last_seen not touched: %v", ex.LastSeen)
	}

	// Analyst confirms criticality: draft tags must drop.
	ex, _ := s.GetByRef(ctx, "host", "host:pg-01")
	high := "high"
	updated, err := s.Update(ctx, ex.ID, UpdateInput{Criticality: &high})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	for _, tag := range updated.Tags {
		if tag == "draft" || strings.HasPrefix(tag, "criticality-suggested:") {
			t.Errorf("draft tag remains after confirmation: %v", updated.Tags)
		}
	}
	if updated.Criticality != "high" {
		t.Errorf("criticality: %q", updated.Criticality)
	}
}

func TestListAndFilter(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for _, a := range []Asset{
		{EntityType: "server", EntityRef: "host:WEB-1", Name: "web-1"},
		{EntityType: "workstation", EntityRef: "host:LAPTOP-9", Name: "laptop-9"},
		{EntityType: "database", EntityRef: "host:PG-PROD", Name: "pg-prod", Criticality: "critical"},
	} {
		if _, err := s.Create(ctx, &a); err != nil {
			t.Fatalf("create %s: %v", a.Name, err)
		}
	}
	all, total, err := s.List(ctx, ListFilter{})
	if err != nil || total != 3 || len(all) != 3 {
		t.Fatalf("list all: %d %d %v", len(all), total, err)
	}
	w, total, err := s.List(ctx, ListFilter{Q: "web"})
	if err != nil || total != 1 || w[0].Name != "web-1" {
		t.Errorf("q filter: %v %d %v", w, total, err)
	}
	crit, total, err := s.List(ctx, ListFilter{Criticality: "critical"})
	if err != nil || total != 1 || crit[0].Name != "pg-prod" {
		t.Errorf("criticality filter: %v %d %v", crit, total, err)
	}
	n, err := s.Count(ctx)
	if err != nil || n != 3 {
		t.Errorf("count: %d %v", n, err)
	}
}

func TestUpdatePartial(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a, _ := s.Create(ctx, &Asset{EntityType: "host", EntityRef: "host:h", Name: "h"})
	owner := "sre-team"
	exposed := true
	updated, err := s.Update(ctx, a.ID, UpdateInput{Owner: &owner, InternetExposed: &exposed})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Owner != "sre-team" || !updated.InternetExposed {
		t.Errorf("partial update: %+v", updated)
	}
	if updated.Name != "h" {
		t.Errorf("untouched field changed: %q", updated.Name)
	}
	// Empty name rejected.
	empty := ""
	if _, err := s.Update(ctx, a.ID, UpdateInput{Name: &empty}); !IsInvalid(err) {
		t.Errorf("empty name update: %v", err)
	}
	// No-op update returns the asset.
	same, err := s.Update(ctx, a.ID, UpdateInput{})
	if err != nil || same.ID != a.ID {
		t.Errorf("no-op update: %v %v", same, err)
	}
}

func TestAliasesSoftwareVulnerabilities(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a, _ := s.Create(ctx, &Asset{EntityType: "server", EntityRef: "host:s", Name: "s"})

	if err := s.AddAlias(ctx, a.ID, "fqdn", "s.internal"); err != nil {
		t.Fatalf("alias: %v", err)
	}
	if err := s.AddAlias(ctx, a.ID, "ip", "10.0.0.5"); err != nil {
		t.Fatalf("alias ip: %v", err)
	}

	now := time.Now().UTC()
	if err := s.UpsertSoftware(ctx, a.ID, Software{Name: "nginx", Vendor: "nginx", Version: "1.25", FirstSeen: now, LastSeen: now, Source: "observed:file"}); err != nil {
		t.Fatalf("software: %v", err)
	}
	// Upsert again with a newer last_seen: no duplicate, version bumped.
	if err := s.UpsertSoftware(ctx, a.ID, Software{Name: "nginx", Version: "1.25", FirstSeen: now, LastSeen: now.Add(time.Hour)}); err != nil {
		t.Fatalf("software upsert: %v", err)
	}

	cvss, epss := 9.8, 0.4
	if err := s.UpsertVulnerability(ctx, a.ID, Vulnerability{CVE: "CVE-2024-1234", Severity: "critical", CVSS: &cvss, EPSS: &epss, ExploitAvailable: "in-the-wild", FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatalf("vuln: %v", err)
	}

	got, err := s.Get(ctx, a.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.Aliases) != 2 || len(got.Software) != 1 {
		t.Errorf("related: aliases=%d software=%d", len(got.Aliases), len(got.Software))
	}
	vulns, err := s.Vulnerabilities(ctx, a.ID)
	if err != nil || len(vulns) != 1 || vulns[0].CVE != "CVE-2024-1234" {
		t.Errorf("vulns: %v %v", vulns, err)
	}

	if err := s.Delete(ctx, a.ID); err != nil {
		t.Errorf("delete: %v", err)
	}
	if _, err := s.Get(ctx, a.ID); err != ErrNotFound {
		t.Errorf("get after delete: %v", err)
	}
}

func TestSuggestCriticality(t *testing.T) {
	type in struct{ entityType, name, os string }
	cases := []struct {
		in   in
		want string
	}{
		{in{"identity_provider", "any", ""}, "critical"},
		{in{"host", "payment-gw", ""}, "critical"},
		{in{"database", "any", ""}, "high"},
		{in{"host", "pg-prod", ""}, "high"},
		{in{"host", "edge-firewall", ""}, "high"},
		{in{"server", "app-server", ""}, "high"},
		{in{"workstation", "ci-builder-3", ""}, "low"},
		{in{"host", "office-pc", ""}, "medium"},
	}
	for _, c := range cases {
		if got := SuggestCriticality(c.in.entityType, c.in.name, c.in.os); got != c.want {
			t.Errorf("SuggestCriticality(%q,%q,%q) = %q want %q", c.in.entityType, c.in.name, c.in.os, got, c.want)
		}
	}
}
