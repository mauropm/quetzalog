// Event → technique mapping. Rules are pure functions (event) →
// {tactic, technique, confidence}; a single event may match multiple rules
// (multi-technique). Results land in the event's `mitre.attack` attribute.
// Behavior chains are NOT produced per-event — they are scenario/
// attack-graph constructs over sequences of mapped events.
package mitre

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
	"quetzalog/pkg/event"
)

//go:embed rules.yaml
var rulesYAML embed.FS

// Mapping is one matched rule's result.
type Mapping struct {
	Tactic        string  `json:"tactic"`
	Technique     string  `json:"technique"`
	TechniqueName string  `json:"technique_name"`
	Confidence    float64 `json:"confidence"`
	RuleID        string  `json:"rule_id"`
}

// RuleWhen is the condition part of a mapping rule. All set conditions
// must hold (AND); unset conditions are wildcards.
type RuleWhen struct {
	// SourceType matches ev.SourceType OR the source_class attribute
	// (normalized taxonomy), case-insensitively.
	SourceType string `yaml:"source_type" json:"source_type,omitempty"`
	// VendorEventID matches the vendor_event_id attribute exactly.
	VendorEventID string `yaml:"vendor_event_id" json:"vendor_event_id,omitempty"`
	// Process is a case-insensitive substring of ev.Process.
	Process string `yaml:"process" json:"process,omitempty"`
	// Service matches ev.Service case-insensitively.
	Service string `yaml:"service" json:"service,omitempty"`
	// EventType / Category / Action / Outcome / User / Host: case-insensitive
	// substring matches on the typed event fields.
	EventType string `yaml:"event_type" json:"event_type,omitempty"`
	Category  string `yaml:"category" json:"category,omitempty"`
	Action    string `yaml:"action" json:"action,omitempty"`
	Outcome   string `yaml:"outcome" json:"outcome,omitempty"`
	User      string `yaml:"user" json:"user,omitempty"`
	Host      string `yaml:"host" json:"host,omitempty"`
	// MessageRegex is a case-insensitive regex on ev.Message.
	MessageRegex string `yaml:"message_regex" json:"message_regex,omitempty"`
	// AttrMatch: field → case-insensitive regex applied to stringified
	// attribute values (special key "message" re-binds to ev.Message).
	AttrMatch map[string]string `yaml:"match" json:"match,omitempty"`
}

// Rule is one mapping rule.
type Rule struct {
	ID          string   `yaml:"id" json:"id"`
	When        RuleWhen `yaml:"when" json:"when"`
	Tactic      string   `yaml:"tactic" json:"tactic"`
	Technique   string   `yaml:"technique" json:"technique"`
	Confidence  float64  `yaml:"confidence" json:"confidence"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
	messageRE   *regexp.Regexp
	attrREs     map[string]*regexp.Regexp
}

// Mapper evaluates mapping rules against events.
type Mapper struct {
	mu    sync.RWMutex
	rules []*Rule
}

// NewMapper loads the embedded rule set. Invalid rules (unknown
// technique/tactic, bad regex) are rejected with an error at load time:
// a broken rule must never silently map events to the wrong technique.
func NewMapper() (*Mapper, error) {
	data, err := rulesYAML.ReadFile("rules.yaml")
	if err != nil {
		return nil, err
	}
	var raw []Rule
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse mapping rules: %w", err)
	}
	m := &Mapper{}
	for i := range raw {
		if err := m.Validate(&raw[i]); err != nil {
			return nil, err
		}
		m.rules = append(m.rules, &raw[i])
	}
	return m, nil
}

// Validate checks a rule's referential integrity and compiles its regexes.
func (m *Mapper) Validate(r *Rule) error {
	if r.ID == "" {
		return fmt.Errorf("mapping rule missing id")
	}
	if r.Tactic == "" || r.Technique == "" {
		return fmt.Errorf("rule %s: tactic and technique required", r.ID)
	}
	if _, ok := TacticName(r.Tactic); !ok {
		return fmt.Errorf("rule %s: unknown tactic %q", r.ID, r.Tactic)
	}
	if _, ok := Lookup(r.Technique); !ok {
		return fmt.Errorf("rule %s: unknown technique %q", r.ID, r.Technique)
	}
	if r.Confidence <= 0 || r.Confidence > 1 {
		return fmt.Errorf("rule %s: confidence must be within (0,1]", r.ID)
	}
	var err error
	if r.When.MessageRegex != "" {
		r.messageRE, err = regexp.Compile("(?i)" + r.When.MessageRegex)
		if err != nil {
			return fmt.Errorf("rule %s: message_regex: %w", r.ID, err)
		}
	}
	for k, re := range r.When.AttrMatch {
		compiled, err := regexp.Compile("(?i)" + re)
		if err != nil {
			return fmt.Errorf("rule %s: match[%s]: %w", r.ID, k, err)
		}
		if r.attrREs == nil {
			r.attrREs = map[string]*regexp.Regexp{}
		}
		r.attrREs[k] = compiled
	}
	return nil
}

// Register adds a runtime-registered rule (extensible at runtime; not
// persisted).
func (m *Mapper) Register(r *Rule) error {
	if err := m.Validate(r); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, existing := range m.rules {
		if existing.ID == r.ID {
			m.rules[i] = r // re-registration replaces
			return nil
		}
	}
	m.rules = append(m.rules, r)
	return nil
}

// Rules lists the active rules (copy).
func (m *Mapper) Rules() []Rule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Rule, len(m.rules))
	for i, r := range m.rules {
		out[i] = *r
	}
	return out
}

// Match returns all technique mappings for an event (deduplicated by
// technique, highest confidence kept).
func (m *Mapper) Match(ev *event.Event) []Mapping {
	if ev == nil {
		return nil
	}
	m.mu.RLock()
	rules := make([]*Rule, len(m.rules))
	copy(rules, m.rules)
	m.mu.RUnlock()

	seen := map[string]Mapping{}
	for _, r := range rules {
		if !r.match(ev) {
			continue
		}
		name, _ := Lookup(r.Technique)
		mp := Mapping{
			Tactic:        r.Tactic,
			Technique:     name.ID,
			TechniqueName: name.Name,
			Confidence:    r.Confidence,
			RuleID:        r.ID,
		}
		if cur, ok := seen[mp.Technique]; !ok || mp.Confidence > cur.Confidence {
			seen[mp.Technique] = mp
		}
	}
	out := make([]Mapping, 0, len(seen))
	for _, mp := range seen {
		out = append(out, mp)
	}
	return out
}

func (r *Rule) match(ev *event.Event) bool {
	w := r.When
	if w.SourceType != "" {
		class := attrString(ev, "source_class")
		if !strings.EqualFold(w.SourceType, ev.SourceType) && !strings.EqualFold(w.SourceType, class) {
			return false
		}
	}
	if w.VendorEventID != "" && !strings.EqualFold(w.VendorEventID, attrString(ev, "vendor_event_id")) {
		return false
	}
	if w.Process != "" && !strings.Contains(strings.ToLower(ev.Process), strings.ToLower(w.Process)) {
		return false
	}
	if w.Service != "" && !strings.Contains(strings.ToLower(ev.Service), strings.ToLower(w.Service)) {
		return false
	}
	if w.EventType != "" && !strings.Contains(strings.ToLower(ev.EventType), strings.ToLower(w.EventType)) {
		return false
	}
	if w.Category != "" && !strings.Contains(strings.ToLower(ev.Category), strings.ToLower(w.Category)) {
		return false
	}
	if w.Action != "" && !strings.Contains(strings.ToLower(ev.Action), strings.ToLower(w.Action)) {
		return false
	}
	if w.Outcome != "" && !strings.Contains(strings.ToLower(ev.Outcome), strings.ToLower(w.Outcome)) {
		return false
	}
	if w.User != "" && !strings.Contains(strings.ToLower(ev.User), strings.ToLower(w.User)) {
		return false
	}
	if w.Host != "" && !strings.Contains(strings.ToLower(ev.Host), strings.ToLower(w.Host)) {
		return false
	}
	if r.messageRE != nil && !r.messageRE.MatchString(ev.Message) {
		return false
	}
	for key, re := range r.attrREs {
		if key == "message" {
			if !re.MatchString(ev.Message) {
				return false
			}
			continue
		}
		if !re.MatchString(attrString(ev, key)) {
			return false
		}
	}
	return true
}

func attrString(ev *event.Event, key string) string {
	if ev.Attributes == nil {
		return ""
	}
	if v, ok := ev.Attributes[key]; ok {
		switch t := v.(type) {
		case string:
			return t
		case float64:
			return fmt.Sprintf("%v", t)
		case bool:
			return fmt.Sprintf("%v", t)
		}
		return ""
	}
	return ""
}

// EventMapper runs the mapping against the event stream on a bounded
// async queue (principle 17: the write path stays mapping-free; results
// land in attributes as they are computed).
type EventMapper struct {
	mapper *Mapper
	db     *sql.DB
	logger *slog.Logger

	queue chan *event.Event
	once  sync.Once
	wg    sync.WaitGroup
}

// NewEventMapper creates the async mapper.
func NewEventMapper(m *Mapper, db *sql.DB, logger *slog.Logger) *EventMapper {
	if logger == nil {
		logger = slog.Default()
	}
	return &EventMapper{mapper: m, db: db, logger: logger, queue: make(chan *event.Event, 1024)}
}

// Enqueue accepts an event; it never blocks (drops when full).
func (e *EventMapper) Enqueue(ev *event.Event) {
	if ev == nil {
		return
	}
	select {
	case e.queue <- ev:
	default:
		e.logger.Warn("mitre mapping queue full, dropping event", "id", ev.ID)
	}
}

// Start launches the workers.
func (e *EventMapper) Start(workers int) {
	if workers <= 0 {
		workers = 2
	}
	for i := 0; i < workers; i++ {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			for ev := range e.queue {
				if err := e.process(context.Background(), ev); err != nil {
					e.logger.Warn("mitre mapping", "event", ev.ID, "error", err)
				}
			}
		}()
	}
}

// Stop drains and closes the queue.
func (e *EventMapper) Stop() {
	e.once.Do(func() { close(e.queue) })
	e.wg.Wait()
}

func (e *EventMapper) process(ctx context.Context, ev *event.Event) error {
	maps := e.mapper.Match(ev)
	if len(maps) == 0 {
		return nil
	}
	b, err := json.Marshal(maps)
	if err != nil {
		return err
	}
	_, err = e.db.ExecContext(ctx,
		`UPDATE events SET attributes = json_set(
			COALESCE(attributes, '{}'), '$."mitre"."attack"', json(?)
		) WHERE id = ?`, string(b), ev.ID)
	if err != nil {
		return fmt.Errorf("store mitre mapping: %w", err)
	}
	return nil
}
