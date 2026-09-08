package event_test

import (
	"strings"
	"testing"
	"time"

	"quetzalog/pkg/event"
)

func TestEventNewAndJSONRoundTrip(t *testing.T) {
	e := event.NewEvent()
	e.Message = "test"
	e.Host = "server01"
	e.Severity = "critical"
	e.Attributes["key"] = "value"

	data, err := event.EventToJSON(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := event.EventFromJSON(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ID != e.ID || got.Message != e.Message || got.Host != e.Host {
		t.Fatalf("round trip mismatch: %#v", got)
	}
}

func TestEventFromJSONFillsDefaults(t *testing.T) {
	got, err := event.EventFromJSON([]byte(`{"message":"hello"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got.ID == "" {
		t.Fatal("missing generated ID")
	}
	if got.ReceivedAt.IsZero() {
		t.Fatal("missing received timestamp")
	}
	if got.Attributes == nil {
		t.Fatal("attributes should be initialized")
	}
}

func TestEventToMapSerializesAttributes(t *testing.T) {
	e := event.NewEvent()
	e.Message = "test"
	e.Attributes["foo"] = "bar"
	e.Raw = []byte("raw")

	m := event.EventToMap(e)
	attrs, ok := m["attributes"].(string)
	if !ok {
		t.Fatalf("attributes should be JSON string, got %T", m["attributes"])
	}
	if !strings.Contains(attrs, `"foo":"bar"`) {
		t.Fatalf("attribute JSON missing: %s", attrs)
	}
	if m["attr.foo"] != "bar" {
		t.Fatalf("attr.foo missing from map")
	}
}

func TestParseSeverity(t *testing.T) {
	tests := map[string]string{
		"INFO":      "info",
		"warn":      "warning",
		"error":     "err",
		"crit":      "critical",
		"emergency": "emergency",
	}
	for in, want := range tests {
		if got := event.ParseSeverity(in); got != want {
			t.Errorf("ParseSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseTimestampFormats(t *testing.T) {
	tbl := []string{
		"2026-01-02T03:04:05Z",
		"2026-01-02 03:04:05",
		"1767346645",
		"1767346645.5",
	}
	for _, s := range tbl {
		if event.ParseTimestamp(s).IsZero() {
			t.Errorf("failed to parse timestamp %q", s)
		}
	}
}

func TestGenerateEventIDUnique(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 50; i++ {
		id := event.GenerateEventID()
		if id == "" {
			t.Fatal("empty event id")
		}
		if ids[id] {
			t.Fatalf("duplicate event id: %s", id)
		}
		ids[id] = true
	}
}

func TestEventsToListHandlesEmpty(t *testing.T) {
	if event.EventsToList(nil) != nil {
		t.Fatal("nil input should return nil")
	}
	list := event.EventsToList([]*event.Event{event.NewEvent()})
	if len(list) != 1 {
		t.Fatalf("want one item, got %d", len(list))
	}
}

func TestEventTimezonesAreUTC(t *testing.T) {
	e := event.NewEvent()
	e.Timestamp = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	m := event.EventToMap(e)
	ts, ok := m["timestamp"].(time.Time)
	if !ok || ts.Location() != time.UTC {
		t.Fatalf("timestamp not UTC: %#v", m["timestamp"])
	}
}