// Package threat holds Phase 3 integration tests: threat-intel provider
// sync feeding the indicator store, event enrichment, and risk
// contributions — plus adversarial TI-feed cases (poisoned payloads,
// conflicting sources) asserting safe failure.
package threat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"quetzalog/internal/database"
	"quetzalog/internal/risk"
	"quetzalog/internal/threatintel"
	"quetzalog/pkg/event"
)

// newFixture boots an in-memory DB with a TI provider (fake Abuse.ch),
// the enricher and the risk store.
func newFixture(t *testing.T) (*threatintel.Store, *threatintel.Enricher, *risk.EntityRiskStore, *httptest.Server) {
	t.Helper()
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/urlhaus/api.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[
			{"url":"https://phish.evil.example/login.php","threat":"phishing","urlstatus":"online"}
		]`))
	})
	mux.HandleFunc("/threatfox/api.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[
			{"name":"phish.evil.example","type":"Domain","threat":"phishing","confidence":95}
		]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	store := threatintel.NewStore(db)
	reg := threatintel.NewRegistry(store)
	reg.Register(threatintel.NewAbuseChProvider(threatintel.AbuseChConfig{BaseURL: srv.URL}))
	riskStore := risk.NewEntityRiskStore(db)
	enricher := threatintel.NewEnricher(store, riskStore, db, nil)
	enricher.Start(1)
	t.Cleanup(enricher.Stop)

	ctx := context.Background()
	if n, err := reg.Sync(ctx, "abuse-ch"); err != nil {
		t.Fatalf("provider sync: %v", err)
	} else if n != 2 {
		t.Fatalf("synced %d indicators, want 2", n)
	}
	return store, enricher, riskStore, srv
}

// TestProviderSyncEnrichRisk runs the full chain: external feed →
// indicator store → event enrichment → explainable risk.
func TestProviderSyncEnrichRisk(t *testing.T) {
	store, enricher, riskStore, _ := newFixture(t)
	ctx := context.Background()

	// The phishing event: its URL and domain both match the feed.
	ev := &event.Event{
		ID:       "evt-phish-1",
		Host:     "mail-gw-01",
		SourceIP: "10.0.0.9",
		Severity: "high",
		Attributes: map[string]any{
			"url":    "https://phish.evil.example/login.php",
			"domain": "PHISH.EVIL.EXAMPLE",
			"email":  "user@phish.evil.example",
		},
	}
	enricher.Enqueue(ev)

	// Wait for the enrichment to land (attribute write is the signal).
	deadline := time.Now().Add(5 * time.Second)
	var matched bool
	for time.Now().Before(deadline) && !matched {
		hits, err := store.Lookup(ctx, "phish.evil.example")
		if err == nil && len(hits) > 0 && hits[0].HitCount > 0 {
			matched = true
		}
		if !matched {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if !matched {
		t.Fatal("enrichment never recorded a hit")
	}

	// The matched domain indicator came from a single feed (ThreatFox) so
	// it carries the single-source discount: 0.95 * 0.9 reliability * 0.8.
	dom, err := store.LookupByType(ctx, "domain", "phish.evil.example")
	if err != nil || len(dom) != 1 {
		t.Fatalf("domain lookup: n=%d err=%v", len(dom), err)
	}
	if dom[0].Confidence <= 0.5 || dom[0].Confidence >= 0.85 {
		t.Errorf("single-source discounted confidence %v, want in (0.5, 0.85)", dom[0].Confidence)
	}
	srcs, _ := store.SourcesOf(ctx, dom[0].ID)
	if len(srcs) != 1 {
		t.Errorf("sources: %+v", srcs)
	}

	// Risk: the host got a contribution (the URL/domain match maps to the
	// event's host entity via the enricher's entity scan).
	er, _ := riskStore.Get(ctx, "host", "mail-gw-01")
	if er == nil || er.RiskScore <= 0 {
		t.Errorf("host risk: %+v, want > 0", er)
	}
	contribs, _ := riskStore.Contributions(ctx, "host", "mail-gw-01", 50)
	if len(contribs) == 0 {
		t.Error("no risk contributions recorded for the host")
	}
}

// TestPoisonedFeedSafeFailure asserts malformed provider payloads never
// corrupt state: bad items are skipped, valid ones land, errors surface.
func TestPoisonedFeedSafeFailure(t *testing.T) {
	mux := http.NewServeMux()
	// A feed that answers with non-JSON: must error cleanly.
	mux.HandleFunc("/urlhaus/api.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>upstream error</html>"))
	})
	mux.HandleFunc("/threatfox/api.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := threatintel.NewStore(db)
	reg := threatintel.NewRegistry(store)
	reg.Register(threatintel.NewAbuseChProvider(threatintel.AbuseChConfig{BaseURL: srv.URL}))

	if _, err := reg.Sync(context.Background(), "abuse-ch"); err == nil {
		t.Error("expected a sync error from a poisoned feed")
	}
	states, _ := store.ProviderStates(context.Background())
	if len(states) != 1 || states[0].LastStatus != "error" {
		t.Errorf("provider state after poison: %+v", states)
	}
	// No indicators imported.
	list, total, _ := store.List(context.Background(), threatintel.ListFilter{})
	if total != 0 || len(list) != 0 {
		t.Errorf("poisoned feed imported indicators: %d", total)
	}
}

// TestConflictingSources asserts two feeds disagreeing on the same
// indicator do not corrupt it: the corroborated best wins, and the
// indicator keeps a single identity.
func TestConflictingSources(t *testing.T) {
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()
	store := threatintel.NewStore(db)

	// Feed A says low-confidence; feed B says high-confidence, same value.
	a, err := store.Upsert(ctx, threatintel.InIndicator{
		Type: "ip", Value: "9.9.9.9", Severity: "low",
		Source: "feed-a", Confidence: 0.2, Reliability: 0.9,
	})
	if err != nil {
		t.Fatalf("upsert a: %v", err)
	}
	b, err := store.Upsert(ctx, threatintel.InIndicator{
		Type: "ip", Value: "9.9.9.9", Severity: "high",
		Source: "feed-b", Confidence: 0.95, Reliability: 0.9,
	})
	if err != nil {
		t.Fatalf("upsert b: %v", err)
	}
	if a.ID != b.ID {
		t.Fatalf("conflicting sources split the indicator: %s vs %s", a.ID, b.ID)
	}
	// Corroborated: best effective = 0.95*0.9 = 0.855 (no single discount).
	if b.Confidence < 0.85 || b.Confidence > 0.9 {
		t.Errorf("conflicting-source confidence %v, want ~0.855", b.Confidence)
	}
}
