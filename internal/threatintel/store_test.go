package threatintel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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

func TestNormalize(t *testing.T) {
	cases := []struct{ typ, in, want string }{
		{"ip", "10.0.0.5", "10.0.0.5"},
		{"ip", " 10.0.0.5 ", "10.0.0.5"},
		{"domain", ".Evil.COM.", "evil.com"},
		{"url", "https://Evil.Example/Path", "https://evil.example/Path"},
		{"hash", "SHA256:ABCDEF", "abcdef"},
		{"hash", "md5:1111", "1111"},
		{"email", "USER@Example.COM", "user@example.com"},
		{"domain", "not-a-domain", "not-a-domain"},
	}
	for _, c := range cases {
		if got := Normalize(c.typ, c.in); got != c.want {
			t.Errorf("Normalize(%s, %q) = %q, want %q", c.typ, c.in, got, c.want)
		}
	}
}

func TestValidateIndicator(t *testing.T) {
	if err := ValidateIndicator(InIndicator{Type: "quantum", Value: "x"}); err == nil {
		t.Error("bad type accepted")
	}
	if err := ValidateIndicator(InIndicator{Type: "ip", Value: "  "}); err == nil {
		t.Error("empty value accepted")
	}
	if err := ValidateIndicator(InIndicator{Type: "ip", Value: "1.2.3.4", Confidence: 1.5}); err == nil {
		t.Error("confidence > 1 accepted")
	}
	if err := ValidateIndicator(InIndicator{Type: "ip", Value: "1.2.3.4", Severity: "apocalyptic"}); err == nil {
		t.Error("bad severity accepted")
	}
}

func TestUpsertAndLookup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	ind, err := s.Upsert(ctx, InIndicator{Type: "domain", Value: ".Evil.com", Severity: "high", Source: "analyst", Confidence: 0.9})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if ind.NormalizedValue != "evil.com" {
		t.Errorf("normalized: %q", ind.NormalizedValue)
	}
	// Single source: 0.9 * 0.8 reliability * 0.8 single-source discount.
	if ind.Confidence < 0.5 || ind.Confidence >= 0.9 {
		t.Errorf("single-source confidence %v not discounted into [0.5,0.9)", ind.Confidence)
	}

	// Lookup by raw and by normalized form.
	hits, err := s.Lookup(ctx, "EVIL.com")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(hits) != 1 || hits[0].ID != ind.ID {
		t.Errorf("lookup hits: %+v", hits)
	}
	hits, err = s.Lookup(ctx, "evil.com")
	if err != nil || len(hits) != 1 {
		t.Errorf("normalized lookup: n=%d err=%v", len(hits), err)
	}
}

func TestConfidenceCorroboration(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	a, _ := s.Upsert(ctx, InIndicator{Type: "ip", Value: "9.9.9.9", Source: "feed-a", Confidence: 0.6, Reliability: 0.9})
	// One source: effective 0.54, discounted → 0.432.
	if a.Confidence > 0.5 {
		t.Errorf("single-source %v too high", a.Confidence)
	}
	// Second, independent source corroborates → max effective (0.9*0.9=0.81),
	// no discount.
	b, err := s.Upsert(ctx, InIndicator{Type: "ip", Value: "9.9.9.9", Source: "feed-b", Confidence: 0.9, Reliability: 0.9})
	if err != nil {
		t.Fatalf("upsert b: %v", err)
	}
	if b.ID != a.ID {
		t.Errorf("corroborating source created a new indicator: %s vs %s", b.ID, a.ID)
	}
	if b.Confidence < 0.8 || b.Confidence > 0.85 {
		t.Errorf("corroborated confidence %v, want ~0.81", b.Confidence)
	}
	srcs, err := s.SourcesOf(ctx, a.ID)
	if err != nil {
		t.Fatalf("sources: %v", err)
	}
	if len(srcs) != 2 {
		t.Errorf("sources: %d, want 2", len(srcs))
	}
}

func TestRecordHitsAndCorrelations(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	a, _ := s.Upsert(ctx, InIndicator{Type: "domain", Value: "evil.com", Source: "analyst"})
	b, _ := s.Upsert(ctx, InIndicator{Type: "ip", Value: "1.1.1.1", Source: "analyst"})

	if err := s.RecordHits(ctx, []string{a.ID, b.ID}, "evt-1"); err != nil {
		t.Fatalf("record hits: %v", err)
	}
	got, _ := s.Get(ctx, a.ID)
	if got.HitCount != 1 {
		t.Errorf("hit count: %d", got.HitCount)
	}
	ids, err := s.CorrelatedIDs(ctx, a.ID, 10)
	if err != nil {
		t.Fatalf("correlations: %v", err)
	}
	if len(ids) != 1 || ids[0] != b.ID {
		t.Errorf("correlated: %v", ids)
	}
	// Duplicate (same event) does not create a new correlation row.
	_ = s.RecordHits(ctx, []string{a.ID, b.ID}, "evt-1")
	ids, _ = s.CorrelatedIDs(ctx, a.ID, 10)
	if len(ids) != 1 {
		t.Errorf("duplicate correlation: %v", ids)
	}
}

func TestActorCampaignMalware(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	ind, _ := s.Upsert(ctx, InIndicator{Type: "domain", Value: "bad.net", Source: "analyst", Actor: "APT-X"})
	a, err := s.GetActor(ctx, "")
	_ = a
	_ = err
	list, err := s.ListActors(ctx, 10)
	if err != nil {
		t.Fatalf("list actors: %v", err)
	}
	if len(list) != 1 || list[0].Name != "APT-X" {
		t.Fatalf("actors: %+v", list)
	}
	full, err := s.GetActor(ctx, list[0].ID)
	if err != nil {
		t.Fatalf("get actor: %v", err)
	}
	if len(full.Indicators) != 1 || full.Indicators[0].ID != ind.ID {
		t.Errorf("actor indicators: %+v", full.Indicators)
	}

	c, err := s.UpsertCampaign(ctx, Campaign{Name: "op-1", ActorID: list[0].ID})
	if err != nil {
		t.Fatalf("campaign: %v", err)
	}
	camps, _ := s.ListCampaigns(ctx, 10)
	if len(camps) != 1 || camps[0].ID != c.ID || camps[0].ActorID != list[0].ID {
		t.Errorf("campaigns: %+v", camps)
	}

	m, err := s.UpsertMalware(ctx, MalwareFamily{Family: "RansomX"})
	if err != nil {
		t.Fatalf("malware: %v", err)
	}
	mals, _ := s.ListMalware(ctx, 10)
	if len(mals) != 1 || mals[0].Family != "RansomX" || mals[0].ID != m.ID {
		t.Errorf("malware: %+v", mals)
	}
}

// fakeProvider is a test provider; poisoned returns malformed items.
type fakeProvider struct {
	name    string
	inds    []InIndicator
	shouldErr bool
}

func (p *fakeProvider) Name() string { return p.name }
func (p *fakeProvider) Sync(ctx context.Context) ([]InIndicator, error) {
	if p.shouldErr {
		return nil, errors.New("upstream 500")
	}
	return p.inds, nil
}

func TestRegistrySync(t *testing.T) {
	s := newTestStore(t)
	reg := NewRegistry(s)
	reg.Register(&fakeProvider{name: "feed-a", inds: []InIndicator{
		{Type: "domain", Value: "a.example", Severity: "medium"},
		{Type: "ip", Value: "2.2.2.2", Severity: "low"},
		// Poisoned item: invalid type — must be skipped, not fatal.
		{Type: "quantum", Value: "???"},
		// Empty value: skipped.
		{Type: "ip", Value: "   "},
	}})

	n, err := reg.Sync(context.Background(), "feed-a")
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if n != 2 {
		t.Errorf("imported %d, want 2 (poisoned items skipped)", n)
	}
	states, _ := s.ProviderStates(context.Background())
	if len(states) != 1 || states[0].LastStatus != "ok" || states[0].IndicatorCount != 2 {
		t.Errorf("state: %+v", states)
	}
	// Re-syncing is idempotent: the same indicators upsert, no duplicates.
	if n, err := reg.Sync(context.Background(), "feed-a"); err != nil || n != 2 {
		t.Errorf("re-sync: n=%d err=%v, want 2/nil", n, err)
	}
	list, total, err := s.List(context.Background(), ListFilter{Limit: 100})
	if err != nil || total != 2 || len(list) != 2 {
		t.Errorf("re-sync created duplicates: total=%d err=%v", total, err)
	}

	// Erroring provider records an error state and returns an error.
	reg.Register(&fakeProvider{name: "feed-b", shouldErr: true})
	if _, err := reg.Sync(context.Background(), "feed-b"); err == nil {
		t.Error("expected sync error")
	}
	states, _ = s.ProviderStates(context.Background())
	var b *ProviderState
	for i := range states {
		if states[i].Provider == "feed-b" {
			b = &states[i]
		}
	}
	if b == nil || b.LastStatus != "error" || !strings.Contains(b.LastError, "upstream 500") {
		t.Errorf("error state: %+v", b)
	}

	total, errs := reg.SyncAll(context.Background())
	if total < 2 || len(errs) != 1 {
		t.Errorf("SyncAll: total=%d errs=%v", total, errs)
	}
	if reg.Names()[0] != "feed-a" {
		t.Errorf("order: %v", reg.Names())
	}
}

func TestInternalProvider(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_, _ = s.Upsert(ctx, InIndicator{Type: "domain", Value: "mine.example", Source: "analyst"})

	p := NewInternalProvider(s)
	inds, err := p.Sync(ctx)
	if err != nil {
		t.Fatalf("internal sync: %v", err)
	}
	if len(inds) != 1 || inds[0].Value != "mine.example" {
		t.Errorf("internal provider: %+v", inds)
	}
}

func TestAbuseChProvider(t *testing.T) {
	// URLhaus returns one indicator per line; a poisoned feed must not
	// crash or import junk.
	mux := http.NewServeMux()
	mux.HandleFunc("/urlhaus/api.php", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"url":"http://evil.example/phish.php","threat":"phishing","urlstatus":"online","lastseen":"2026-09-15 10:00:00"},
			{"url":"","threat":"botnet","urlstatus":"offline"},
			{"url":"http://ok.example/","threat":"malware","urlstatus":"online"}
		]`))
	})
	mux.HandleFunc("/threatfox/api.php", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[
			{"name":"botnet.example","type":"Domain","threat":"botnet","confidence":90,"firstseen":"2026-09-01"},
			{"name":"","type":"IP","threat":"x","confidence":10},
			{"name":"weird","type":"SomethingNew","threat":"x","confidence":10}
		]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := NewAbuseChProvider(AbuseChConfig{BaseURL: srv.URL, UserAgent: "quetzalog-test"})
	inds, err := p.Sync(context.Background())
	if err != nil {
		t.Fatalf("abusech sync: %v", err)
	}
	// urlhaus: 2 valid (empty URL skipped). threatfox: 1 valid (empty name
	// and unknown type skipped). Total 3, all quarantined with provenance.
	if len(inds) != 3 {
		t.Fatalf("abusech indicators: %d, want 3: %+v", len(inds), inds)
	}
	var sawDomain bool
	for _, in := range inds {
		if in.Source != "abuse-ch/urlhaus" && in.Source != "abuse-ch/threatfox" {
			t.Errorf("source: %q", in.Source)
		}
		if in.Type == "" || in.Value == "" {
			t.Errorf("malformed indicator: %+v", in)
		}
		if in.Type == "domain" && in.Value == "botnet.example" {
			sawDomain = true
		}
	}
	if !sawDomain {
		t.Errorf("expected threatfox domain indicator: %+v", inds)
	}
	_ = time.Now()
}
