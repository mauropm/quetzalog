package event

import (
	"testing"
)

func TestProvenanceSetsRawAndAttributes(t *testing.T) {
	e := &Event{}
	Provenance(e, []byte("<14>msg"), "syslog", "syslog3164", "1", "syslog")

	if string(e.Raw) != "<14>msg" {
		t.Errorf("raw: got %q", e.Raw)
	}
	if e.RawFormat != "syslog" {
		t.Errorf("raw_format: got %q", e.RawFormat)
	}
	if e.Attributes[AttrParser] != "syslog3164" {
		t.Errorf("parser attr: got %v", e.Attributes[AttrParser])
	}
	if e.Attributes[AttrParserVersion] != "1" {
		t.Errorf("parser_version attr: got %v", e.Attributes[AttrParserVersion])
	}
	if e.Attributes[AttrCollector] != "syslog" {
		t.Errorf("collector attr: got %v", e.Attributes[AttrCollector])
	}
}

func TestProvenanceNilEvent(t *testing.T) {
	Provenance(nil, []byte("x"), "syslog", "p", "1", "c") // must not panic
}

func TestProvenanceOverwritesPayloadKeys(t *testing.T) {
	e := &Event{Attributes: map[string]any{"parser": "spoofed", "parser_version": "99"}}
	Provenance(e, nil, "", "json", "1", "json")
	if e.Attributes[AttrParser] != "json" {
		t.Errorf("payload parser key not overridden: %v", e.Attributes[AttrParser])
	}
	if e.Attributes[AttrParserVersion] != "1" {
		t.Errorf("payload parser_version key not overridden: %v", e.Attributes[AttrParserVersion])
	}
}

func TestProvenanceEmptyParserKeepsRawFormat(t *testing.T) {
	e := &Event{RawFormat: "raw"}
	Provenance(e, nil, "", "", "", "hec")
	if e.RawFormat != "raw" {
		t.Errorf("raw_format changed by empty provenance: %q", e.RawFormat)
	}
	if e.Attributes[AttrCollector] != "hec" {
		t.Errorf("collector: got %v", e.Attributes[AttrCollector])
	}
}
