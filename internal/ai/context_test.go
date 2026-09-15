package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"quetzalog/internal/database"
	"quetzalog/internal/events"
	"quetzalog/internal/findings"
	"quetzalog/pkg/event"
)

func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }

func TestContextIncludesAssetContextAndGaps(t *testing.T) {
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	fs := findings.NewStore(db)
	cb := NewContextBuilder(fs, nil).
		WithAssets(func(ctx context.Context, host string) *HostAsset {
			if host != "db1" {
				return nil
			}
			return &HostAsset{
				Name:          "db1",
				EntityType:    "server",
				Criticality:   "critical",
				InternetExposed: false,
				TelemetryCoverage: &CoveragePct{
					Pct:     45,
					Missing: []string{"os.linux.journal", "net.flow"},
				},
				Vulnerabilities: []VulnBrief{{CVE: "CVE-2024-0001", ExploitAvailable: "in-the-wild"}},
			}
		})

	f := &findings.Finding{
		ID:       "f-1",
		Title:    "Suspicious login",
		Severity: "critical",
		Status:   "new",
		Host:     "db1",
	}
	fctx, err := cb.Build(context.Background(), f, 10)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if fctx.AssetContext == nil || len(fctx.AssetContext.Hosts) != 1 {
		t.Fatalf("asset_context missing: %+v", fctx.AssetContext)
	}
	h := fctx.AssetContext.Hosts[0]
	if h.Name != "db1" || h.Criticality != "critical" {
		t.Errorf("asset block: %+v", h)
	}
	if h.TelemetryCoverage == nil || h.TelemetryCoverage.Pct != 45 || len(h.TelemetryCoverage.Missing) != 2 {
		t.Errorf("telemetry coverage: %+v", h.TelemetryCoverage)
	}
	if len(h.Vulnerabilities) != 1 || h.Vulnerabilities[0].CVE != "CVE-2024-0001" {
		t.Errorf("vulnerabilities: %+v", h.Vulnerabilities)
	}
	// Gaps are present and named after the missing telemetry.
	if len(fctx.TelemetryGaps) != 2 {
		t.Errorf("telemetry_gaps: %v", fctx.TelemetryGaps)
	}
	for _, g := range fctx.TelemetryGaps {
		if !strings.Contains(g, "db1") {
			t.Errorf("gap should name the asset: %q", g)
		}
	}
}

func TestContextOmitsSectionsWhenHooksUnset(t *testing.T) {
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	cb := NewContextBuilder(findings.NewStore(db), nil)
	f := &findings.Finding{ID: "f-2", Title: "t", Severity: "info", Host: "h1"}
	fctx, err := cb.Build(context.Background(), f, 10)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if fctx.AssetContext != nil || fctx.ThreatIntel != nil || fctx.Mitre != nil ||
		fctx.AttackGraph != nil || fctx.PriorAnalyses != nil || fctx.TelemetryGaps != nil {
		t.Errorf("sections must be omitted without hooks: %+v", fctx)
	}
}

func TestContextEventProvenanceAndMitre(t *testing.T) {
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	es := events.NewStore(db)

	ev := event.NewEvent()
	ev.ID = "e-100"
	ev.Timestamp = time.Now().UTC()
	ev.Host = "web-01"
	ev.User = "svc"
	ev.SourceIP = "10.0.0.1"
	ev.DestinationIP = "203.0.113.5"
	ev.Message = "powershell -enc xyz"
	ev.Severity = "error"
	ev.Attributes = map[string]any{
		"domain": "evil.example",
		"mitre": map[string]any{
			"attack": []any{
				map[string]any{"technique": "T1059.001", "technique_name": "PowerShell", "tactic": "TA0002", "confidence": 0.9},
			},
		},
	}
	if err := es.Create(context.Background(), ev); err != nil {
		t.Fatalf("add event: %v", err)
	}

	fs := findings.NewStore(db)
	f := &findings.Finding{
		ID:       "f-3",
		Title:    "PS exec",
		Severity: "high",
		Status:   "new",
		Host:     "web-01",
		EventIDs: []string{"e-100"},
	}
	fctx, err := NewContextBuilder(fs, es).Build(context.Background(), f, 10)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(fctx.Events) != 1 {
		t.Fatalf("events: %d", len(fctx.Events))
	}
	e := fctx.Events[0]
	if e.ID != "e-100" {
		t.Errorf("event id provenance lost: %+v", e)
	}
	// Entity extraction (depth-1).
	if !contains(e.Entities, "ip:203.0.113.5") || !contains(e.Entities, "host:web-01") ||
		!contains(e.Entities, "domain:evil.example") {
		t.Errorf("entities: %v", e.Entities)
	}
	// MITRE mapping decoded with evidence event.
	if len(e.Mitre) != 1 || e.Mitre[0].Technique != "T1059.001" {
		t.Errorf("mitre: %+v", e.Mitre)
	}
	if fctx.Mitre == nil || len(fctx.Mitre.Observed) != 1 ||
		fctx.Mitre.Observed[0].ID != "T1059.001" ||
		!contains(fctx.Mitre.Observed[0].EvidenceEvents, "e-100") {
		t.Errorf("mitre_context: %+v", fctx.Mitre)
	}
	if fctx.Mitre.KillChainPosition != "TA0002" {
		t.Errorf("kill_chain_position: %q", fctx.Mitre.KillChainPosition)
	}
	// Entity summary carries the ip + domain.
	if !contains(fctx.Entities.IPs, "203.0.113.5") || !contains(fctx.Entities.Domains, "evil.example") {
		t.Errorf("entities summary: %+v", fctx.Entities)
	}
}

func TestContextTIAndScenarioAndGraph(t *testing.T) {
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	es := events.NewStore(db)
	ev := event.NewEvent()
	ev.ID = "e-200"
	ev.Timestamp = time.Now().UTC()
	ev.Host = "web-01"
	ev.Message = "outbound to 203.0.113.5"
	ev.Severity = "warning"
	if err := es.Create(context.Background(), ev); err != nil {
		t.Fatalf("add event: %v", err)
	}

	fs := findings.NewStore(db)
	f := &findings.Finding{
		ID:       "f-4",
		Title:    "C2",
		Severity: "high",
		Status:   "new",
		Host:     "web-01",
		EventIDs: []string{"e-200"},
		Entities: []string{"ip:203.0.113.5"},
	}
	cb := NewContextBuilder(fs, es).
		WithThreatIntel(func(ctx context.Context, values []string) []TIHit {
			for _, v := range values {
				if v == "203.0.113.5" {
					return []TIHit{{
						Value: "203.0.113.5", Type: "ip", Severity: "high",
						Source:       "misp",
						Confidence:   TIConfidence{SourceReliability: 0.8, IndicatorConfidence: 0.9, Corroboration: 3},
						Actors:       []string{"APT-X"},
						FirstSeen:    time.Now().UTC().Add(-90 * 24 * time.Hour),
						LastSeen:     time.Now().UTC(),
						References:   []string{"https://feed.example/ref1"},
					}}
				}
			}
			return nil
		}).
		WithScenarios(func(ctx context.Context, host string) *ScenarioBrief {
			return &ScenarioBrief{
				Name: "Web compromise", Status: "active",
				Observed:     []string{"T1190"},
				ExpectedNext: []string{"T1059"},
				Unknown:      []string{"T1021 — no SMB telemetry"},
			}
		}).
		WithAttackGraph(func(ctx context.Context, hosts []string) *AttackGraphBrief {
			return &AttackGraphBrief{
				CompromisedNodes: []string{"host:web-01"},
				AtRiskNodes:      []string{"host:db-01"},
				Edges:            []GraphEdge{{From: "host:web-01", To: "host:db-01", Relation: "connects_to", State: "observed"}},
			}
		}).
		WithPriorAnalyses(func(ctx context.Context, ids []string) []PriorAnalysis {
			return []PriorAnalysis{{ID: "a-1", FindingID: "f-0", Summary: "old", Decision: "dismiss", Reason: "false positive"}}
		})

	fctx, err := cb.Build(context.Background(), f, 10)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(fctx.ThreatIntel) != 1 || fctx.ThreatIntel[0].Value != "203.0.113.5" ||
		len(fctx.ThreatIntel[0].Actors) != 1 {
		t.Errorf("threat_intel: %+v", fctx.ThreatIntel)
	}
	if fctx.Mitre == nil || fctx.Mitre.ScenarioRun == nil || fctx.Mitre.ScenarioRun.Name != "Web compromise" {
		t.Errorf("scenario run missing: %+v", fctx.Mitre)
	}
	if fctx.AttackGraph == nil || len(fctx.AttackGraph.CompromisedNodes) != 1 || len(fctx.AttackGraph.Edges) != 1 {
		t.Errorf("attack_graph: %+v", fctx.AttackGraph)
	}
	if len(fctx.PriorAnalyses) != 1 || fctx.PriorAnalyses[0].Decision != "dismiss" {
		t.Errorf("prior_analyses: %+v", fctx.PriorAnalyses)
	}
}

func TestContextLegacyJSONStillReadable(t *testing.T) {
	// v1 contexts stored a telemetry_gaps list of objects and a flat assets
	// list; the v2 reader must drop those without failing.
	legacy := `{
		"finding": {"id":"f-x","title":"old","severity":"high","status":"new","match_count":3},
		"events": [{"id":"e-1","timestamp":"2026-01-01T00:00:00Z","message":"m"}],
		"assets": [{"name":"h1","criticality":"high"}],
		"telemetry_gaps": [{"asset":"h1","coverage_pct":45,"missing":["x"]}]
	}`
	var c FindingContext
	if err := jsonUnmarshal(legacy, &c); err != nil {
		t.Fatalf("legacy context unmarshal: %v", err)
	}
	if c.Finding.ID != "f-x" || len(c.Events) != 1 {
		t.Errorf("legacy context lost: %+v", c)
	}
	if len(c.TelemetryGaps) != 0 {
		t.Errorf("legacy telemetry_gaps should be dropped: %v", c.TelemetryGaps)
	}
}

func TestContextBudgetDropsOldEvents(t *testing.T) {
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	es := events.NewStore(db)
	fs := findings.NewStore(db)

	const n = 400
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		ev := event.NewEvent()
		ev.ID = "e-" + itoa(i)
		ev.Timestamp = time.Now().UTC()
		ev.Message = strings.Repeat("x", 300)
		ev.Severity = "info"
		if err := es.Create(context.Background(), ev); err != nil {
			t.Fatalf("add event: %v", err)
		}
		ids = append(ids, ev.ID)
	}
	f := &findings.Finding{ID: "f-5", Title: "big", Severity: "high", Status: "new", EventIDs: ids}
	fctx, err := NewContextBuilder(fs, es).Build(context.Background(), f, 100)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if fctx.jsonSize() > maxContextJSONBytes {
		t.Errorf("context over budget: %d bytes", fctx.jsonSize())
	}
	// The most recent events survive the trim.
	if len(fctx.Events) == 0 {
		t.Errorf("all events dropped")
	}
	if fctx.Events[len(fctx.Events)-1].ID != ids[len(ids)-1] {
		t.Errorf("most recent event not kept: last=%s want=%s",
			fctx.Events[len(fctx.Events)-1].ID, ids[len(ids)-1])
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
