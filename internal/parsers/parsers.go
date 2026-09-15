// Package parsers owns format-specific log parsing for Quetzalog.
//
// Parsers are pure functions from raw bytes to a Parsed record; they never
// touch the event model, storage, or any external service. Ingestion
// sources (collectors) compose parsers with their transports, stamp
// provenance (pkg/event.Provenance), and build canonical events.
package parsers

import (
	"time"

	"quetzalog/pkg/event"
)

// Parsed is the parser-level representation of one log record: everything a
// collector needs to fill a canonical event, before normalization.
type Parsed struct {
	Timestamp  time.Time
	Severity   string
	Host       string
	Source     string
	User       string
	Message    string
	SourceIP   string
	DestIP     string
	SourcePort int
	DestPort   int
	ProcessID  string
	EventType  string
	Attributes map[string]any
}

// Attrs ensures the map is non-nil for callers that write into it.
func (p *Parsed) Attrs() map[string]any {
	if p.Attributes == nil {
		p.Attributes = make(map[string]any)
	}
	return p.Attributes
}

// Parser parses records of one format. Parse returns ok=false when the
// input does not match the format (callers fall through to the next
// candidate or to plain-text handling).
type Parser interface {
	Name() string
	Version() string
	Parse(raw []byte) (*Parsed, bool)
}

// Registry orders parsers for auto-detection.
type Registry struct {
	order []Parser
	byName map[string]Parser
}

// New creates the default registry: unambiguous prefixed formats first
// (CEF, LEEF), then GELF (JSON heuristic), then syslog v2, v1, and finally
// plain text, which always matches.
func New() *Registry {
	r := &Registry{byName: make(map[string]Parser)}
	r.order = []Parser{
		cefParser{},
		leefParser{},
		gelfParser{},
		syslog5424Parser{},
		syslog3164Parser{},
		plainParser{},
	}
	for _, p := range r.order {
		r.byName[p.Name()] = p
	}
	return r
}

// Default is the shared registry.
var Default = New()

// Auto detects the format of raw and returns its parse result plus the
// parser name. plain always matches, so this never fails.
func (r *Registry) Auto(raw []byte) (*Parsed, string) {
	for _, p := range r.order {
		if out, ok := p.Parse(raw); ok {
			return out, p.Name()
		}
	}
	out, _ := plainParser{}.Parse(raw)
	return out, "plain"
}

// DetectSpecial tries only the unambiguous non-syslog formats (CEF, LEEF,
// GELF). Used where plain-text lines may occasionally be one of those
// formats but syslog is not in scope. Returns ok=false when none match.
func (r *Registry) DetectSpecial(raw []byte) (*Parsed, string, bool) {
	for _, p := range []Parser{cefParser{}, leefParser{}, gelfParser{}} {
		if out, ok := p.Parse(raw); ok {
			return out, p.Name(), true
		}
	}
	return nil, "", false
}

// Get returns a parser by name.
func (r *Registry) Get(name string) (Parser, bool) {
	p, ok := r.byName[name]
	return p, ok
}

// Fill applies a parse result to a canonical event. Only fields the
// parser actually produced are written, so collector-set fields
// (source type, timestamps, ...) are never clobbered. Attributes are
// merged into the event's map.
func Fill(ev *event.Event, p *Parsed) {
	if ev == nil || p == nil {
		return
	}
	if !p.Timestamp.IsZero() {
		ev.Timestamp = p.Timestamp
	}
	if p.Severity != "" {
		ev.Severity = p.Severity
	}
	if p.Host != "" {
		ev.Host = p.Host
	}
	if p.Source != "" {
		ev.Source = p.Source
	}
	if p.User != "" {
		ev.User = p.User
	}
	if p.Message != "" {
		ev.Message = p.Message
	}
	if p.SourceIP != "" {
		ev.SourceIP = p.SourceIP
	}
	if p.DestIP != "" {
		ev.DestinationIP = p.DestIP
	}
	if p.SourcePort != 0 {
		ev.SourcePort = p.SourcePort
	}
	if p.DestPort != 0 {
		ev.DestinationPort = p.DestPort
	}
	if p.ProcessID != "" {
		ev.ProcessID = p.ProcessID
	}
	if p.EventType != "" {
		ev.EventType = p.EventType
	}
	for k, v := range p.Attributes {
		if ev.Attributes == nil {
			ev.Attributes = make(map[string]any)
		}
		ev.Attributes[k] = v
	}
}
