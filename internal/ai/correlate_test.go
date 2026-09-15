package ai

import (
	"context"
	"strings"
	"testing"
)

func TestCorrelationQueryShape(t *testing.T) {
	q := correlationQuery(CorrelateEnt{
		Users: []string{"jsmith"},
		Hosts: []string{"web-01"},
		IPs:   []string{"10.0.0.5"},
	})
	want := `user="jsmith" OR host="web-01" OR source_ip="10.0.0.5" OR destination_ip="10.0.0.5"`
	if q != want {
		t.Errorf("query:\n got %q\nwant %q", q, want)
	}
}

func TestCorrelationQueryEmpty(t *testing.T) {
	if q := correlationQuery(CorrelateEnt{}); q != "" {
		t.Errorf("expected empty query, got %q", q)
	}
}

func TestValidIP(t *testing.T) {
	for ip, ok := range map[string]bool{
		"10.0.0.5":     true,
		"0.0.0.0":      true,
		"255.255.255.255": true,
		"999.1.1.1":    false,
		"1.2.3":        false,
		"1.2.3.4.5":    false,
		"1.2.3.a":      false,
		"":             false,
	} {
		if got := validIP(ip); got != ok {
			t.Errorf("validIP(%q) = %v, want %v", ip, got, ok)
		}
	}
}

// TestCorrelateQueryEntities verifies the service-level flow: structured
// entities from the persisted context plus IPs the model named only in its
// recommendation text end up in the SPL filter.
func TestCorrelateQueryEntities(t *testing.T) {
	fake := &fakeProvider{name: "fake", out: strings.ReplaceAll(validAnalysisJSON(),
		`"description": "Review the successful login and determine whether the source IP is trusted."`,
		`"description": "Review authentication failures from 10.0.0.55 between the workstation and web-01."`)}
	svc, fs, _ := newServiceEnv(t, fake)
	f := seedFinding(t, fs, "high")

	row, err := svc.AnalyzeFinding(context.Background(), f.ID, false)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	res, err := svc.CorrelateQuery(context.Background(), row.ID)
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if !strings.Contains(res.Query, `user="jsmith"`) || !strings.Contains(res.Query, `host="web-01"`) {
		t.Errorf("query missing structured entities: %q", res.Query)
	}
	if !strings.Contains(res.Query, `source_ip="10.0.0.1"`) {
		t.Errorf("query missing context IP: %q", res.Query)
	}
	if !strings.Contains(res.Query, `destination_ip="10.0.0.55"`) {
		t.Errorf("query missing text-named IP 10.0.0.55: %q", res.Query)
	}
}

func TestCorrelateQueryWindowFromText(t *testing.T) {
	fake := &fakeProvider{name: "fake", out: strings.ReplaceAll(validAnalysisJSON(),
		`"description": "Review the successful login and determine whether the source IP is trusted."`,
		`"description": "Review the window 2026-09-14T20:00:00Z through 2026-09-14T21:30:00Z on web-01."`)}
	svc, fs, _ := newServiceEnv(t, fake)
	f := seedFinding(t, fs, "high")

	row, err := svc.AnalyzeFinding(context.Background(), f.ID, false)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	res, err := svc.CorrelateQuery(context.Background(), row.ID)
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if res.Earliest != "2026-09-14T20:00:00Z" || res.Latest != "2026-09-14T21:30:00Z" {
		t.Errorf("window: %q -> %q", res.Earliest, res.Latest)
	}
}

func TestCorrelateQueryWindowFallbackToEvents(t *testing.T) {
	fake := &fakeProvider{name: "fake", out: validAnalysisJSON()}
	svc, fs, _ := newServiceEnv(t, fake)
	f := seedFinding(t, fs, "high")

	row, err := svc.AnalyzeFinding(context.Background(), f.ID, false)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	res, err := svc.CorrelateQuery(context.Background(), row.ID)
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if res.Earliest == "" || res.Latest == "" {
		t.Errorf("expected event-based window, got %q -> %q", res.Earliest, res.Latest)
	}
}

func TestCorrelateQueryMissingAnalysis(t *testing.T) {
	svc, _, _ := newServiceEnv(t, &fakeProvider{name: "fake", out: validAnalysisJSON()})
	if _, err := svc.CorrelateQuery(context.Background(), "no-such-id"); err == nil {
		t.Error("expected error for unknown analysis")
	}
}
