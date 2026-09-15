package detections_test

import (
	"context"
	"strings"
	"testing"

	"quetzalog/internal/detections"
	"quetzalog/internal/spl/executor"
)

func TestCatalog_List(t *testing.T) {
	entries, err := detections.ListCatalog()
	if err != nil {
		t.Fatalf("list catalog: %v", err)
	}
	if len(entries) < 3 {
		t.Fatalf("catalog entries: %d, want >= 3", len(entries))
	}
	det, hunt := 0, 0
	for _, e := range entries {
		if e.Name == "" || e.Title == "" || e.Rule.Query == "" {
			t.Errorf("incomplete entry: %+v", e)
		}
		if e.Category == "detection" {
			det++
		}
		if e.Hunting {
			hunt++
		}
	}
	if det == 0 {
		t.Errorf("no detection entries")
	}
	if hunt == 0 {
		t.Errorf("no hunting entries")
	}
}

func TestCatalog_Install(t *testing.T) {
	store, _, db := setup(t)
	ctx := context.Background()
	_ = db

	entry, err := detections.CatalogEntryByName("brute_force_login")
	if err != nil {
		t.Fatalf("lookup entry: %v", err)
	}
	installed, err := store.InstallCatalog(ctx, entry)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if installed.Name != entry.Title {
		t.Errorf("name: %q, want %q", installed.Name, entry.Title)
	}
	if installed.Version != entry.Version {
		t.Errorf("version: %d, want %d", installed.Version, entry.Version)
	}
	if !installed.Enabled {
		t.Errorf("installed rule should be enabled")
	}
	found := false
	for _, tag := range installed.Tags {
		if tag == "catalog:brute_force_login" {
			found = true
		}
	}
	if !found {
		t.Errorf("tags missing catalog:<name>: %v", installed.Tags)
	}

	// Reinstall upgrades in place (same ID, version stamped) instead of
	// duplicating.
	again, err := store.InstallCatalog(ctx, entry)
	if err != nil {
		t.Fatalf("reinstall: %v", err)
	}
	if again.ID != installed.ID {
		t.Errorf("reinstall created a new rule (id %q vs %q)", again.ID, installed.ID)
	}
	list, _ := store.List(ctx)
	if len(list) != 1 {
		t.Errorf("rules after reinstall: %d, want 1", len(list))
	}
}

func TestCatalog_InstallPreservesSuppression(t *testing.T) {
	store, _, _ := setup(t)
	ctx := context.Background()

	entry, err := detections.CatalogEntryByName("brute_force_login")
	if err != nil {
		t.Fatalf("lookup entry: %v", err)
	}
	installed, err := store.InstallCatalog(ctx, entry)
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	// Analyst suppresses the rule, then the catalog upgrades it.
	if err := store.Suppress(ctx, installed.ID, "qa", "noise"); err != nil {
		t.Fatalf("suppress: %v", err)
	}
	_, err = store.InstallCatalog(ctx, entry)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}

	fresh, err := store.GetByID(ctx, installed.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !fresh.Suppressed {
		t.Errorf("catalog upgrade unsuppressed the rule")
	}
	if fresh.SuppressReason != "noise" {
		t.Errorf("suppress reason lost: %q", fresh.SuppressReason)
	}
}

func TestCatalog_UnknownEntry(t *testing.T) {
	_, err := detections.CatalogEntryByName("nope")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not-found error, got: %v", err)
	}
}

func TestCatalog_HuntingQueriesExecute(t *testing.T) {
	// Every kind=spl catalog entry must run through the real SPL engine
	// (syntax errors here would only surface at runtime, spec §54).
	_, _, db := setup(t)
	entries, err := detections.ListCatalog()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	checked := 0
	for _, e := range entries {
		if e.Rule.Kind != "spl" {
			continue
		}
		if _, err := executor.Run(context.Background(), db, e.Rule.Query, executor.RunOptions{Limit: 10}); err != nil {
			t.Errorf("catalog %s does not execute: %v", e.Name, err)
		}
		checked++
	}
	if checked == 0 {
		t.Errorf("no spl catalog entries checked")
	}
}
