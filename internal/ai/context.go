package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"quetzalog/internal/events"
	"quetzalog/internal/findings"
)

// maxContextJSONBytes bounds the serialized evidence snapshot. The context
// is deliberately compact: the model receives structured facts, never raw
// log floods.
const maxContextJSONBytes = 48 * 1024

// maxEventMessage trims individual event messages to keep the context tight.
const maxEventMessage = 240

// FindingContext is the structured evidence snapshot sent to the model:
// the finding itself, its surrounding events, related findings and the
// entities involved. No credentials or configuration data are included.
type FindingContext struct {
	Finding   FindingInfo   `json:"finding"`
	Events    []EventInfo   `json:"events"`
	Related   []FindingInfo `json:"related_findings"`
	Entities  EntitySummary `json:"entities"`
}

// FindingInfo is a compact finding representation.
type FindingInfo struct {
	ID             string    `json:"id"`
	Title          string    `json:"title"`
	Description    string    `json:"description,omitempty"`
	Severity       string    `json:"severity"`
	Status         string    `json:"status"`
	DetectionName  string    `json:"detection_name,omitempty"`
	MITRETactic    string    `json:"mitre_tactic,omitempty"`
	MITRETechnique string    `json:"mitre_technique,omitempty"`
	MatchCount     int       `json:"match_count"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
}

// EventInfo is a compact event representation.
type EventInfo struct {
	Timestamp time.Time `json:"timestamp"`
	Severity  string    `json:"severity"`
	Source    string    `json:"source,omitempty"`
	Host      string    `json:"host,omitempty"`
	User      string    `json:"user,omitempty"`
	Message   string    `json:"message"`
	EventType string    `json:"event_type,omitempty"`
	Category  string    `json:"category,omitempty"`
	Action    string    `json:"action,omitempty"`
	Outcome   string    `json:"outcome,omitempty"`
}

// EntitySummary groups the entities involved in the finding.
type EntitySummary struct {
	IPs       []string `json:"ip_addresses,omitempty"`
	Users     []string `json:"users,omitempty"`
	Hosts     []string `json:"hosts,omitempty"`
	Sources   []string `json:"sources,omitempty"`
	Processes []string `json:"processes,omitempty"`
}

// ContextBuilder assembles the analyst context from a finding.
type ContextBuilder struct {
	findings *findings.Store
	events   *events.Store
}

// NewContextBuilder creates a context builder over the finding and event stores.
func NewContextBuilder(findings *findings.Store, evStore *events.Store) *ContextBuilder {
	return &ContextBuilder{findings: findings, events: evStore}
}

// Build collects the finding's events (bounded), related findings and the
// entity summary. maxEvents <= 0 falls back to 100.
func (b *ContextBuilder) Build(ctx context.Context, f *findings.Finding, maxEvents int) (*FindingContext, error) {
	if f == nil {
		return nil, fmt.Errorf("nil finding")
	}
	if maxEvents <= 0 {
		maxEvents = 100
	}

	fctx := &FindingContext{
		Finding: FindingInfo{
			ID:               f.ID,
			Title:            f.Title,
			Description:      truncate(f.Description, 500),
			Severity:         f.Severity,
			Status:           f.Status,
			DetectionName:    f.DetectionName,
			MITRETactic:      f.MITRETactic,
			MITRETechnique:   f.MITRETechnique,
			MatchCount:       f.MatchCount,
			FirstSeen:        f.FirstSeen,
			LastSeen:         f.LastSeen,
		},
	}

	// Direct events belonging to the finding (newest first in the store).
	ids := f.EventIDs
	if len(ids) > maxEvents {
		ids = ids[len(ids)-maxEvents:] // keep the most recent events
	}
	for _, id := range ids {
		ev, err := b.events.GetByID(ctx, id)
		if err != nil || ev == nil {
			continue
		}
		fctx.Events = append(fctx.Events, EventInfo{
			Timestamp: ev.Timestamp,
			Severity:  ev.Severity,
			Source:    ev.Source,
			Host:      ev.Host,
			User:      ev.User,
			Message:   truncate(ev.Message, maxEventMessage),
			EventType: ev.EventType,
			Category:  ev.Category,
			Action:    ev.Action,
			Outcome:   ev.Outcome,
		})
	}

	// Related findings through shared entities.
	seen := map[string]bool{f.ID: true}
	for _, ent := range f.Entities {
		parts := strings.SplitN(ent, ":", 2)
		if len(parts) != 2 || parts[1] == "" {
			continue
		}
		et, ev := parts[0], parts[1]
		if et != "user" && et != "host" && et != "ip" {
			continue
		}
		related, err := b.findings.RelatedByEntity(ctx, et, ev, 5)
		if err != nil {
			continue
		}
		for _, r := range related {
			if seen[r.ID] {
				continue
			}
			seen[r.ID] = true
			fctx.Related = append(fctx.Related, FindingInfo{
				ID:            r.ID,
				Title:         r.Title,
				Severity:      r.Severity,
				Status:        r.Status,
				DetectionName: r.DetectionName,
				FirstSeen:     r.FirstSeen,
				LastSeen:      r.LastSeen,
			})
			if len(fctx.Related) >= 5 {
				break
			}
		}
		if len(fctx.Related) >= 5 {
			break
		}
	}

	// Entity summary.
	sum := &fctx.Entities
	sum.IPs = append(sum.IPs, nonEmpty(f.SourceIP, f.DestinationIP)...)
	sum.Users = append(sum.Users, f.User)
	sum.Hosts = append(sum.Hosts, f.Host)
	for _, ent := range f.Entities {
		parts := strings.SplitN(ent, ":", 2)
		if len(parts) != 2 || parts[1] == "" {
			continue
		}
		switch parts[0] {
		case "ip", "source_ip", "destination_ip":
			sum.IPs = append(sum.IPs, parts[1])
		case "user":
			sum.Users = append(sum.Users, parts[1])
		case "host":
			sum.Hosts = append(sum.Hosts, parts[1])
		case "process":
			sum.Processes = append(sum.Processes, parts[1])
		}
	}
	for _, ev := range fctx.Events {
		sum.Sources = append(sum.Sources, ev.Source)
	}
	fctx.Entities = EntitySummary{
		IPs:       unique(sum.IPs),
		Users:     unique(sum.Users),
		Hosts:     unique(sum.Hosts),
		Sources:   unique(sum.Sources),
		Processes: unique(sum.Processes),
	}

	// Enforce the context size budget by dropping oldest events.
	for i := 0; i < 20; i++ {
		if fctx.jsonSize() <= maxContextJSONBytes {
			break
		}
		if len(fctx.Events) == 0 {
			break
		}
		fctx.Events = fctx.Events[1:]
	}
	return fctx, nil
}

func (c *FindingContext) jsonSize() int {
	b, _ := json.Marshal(c)
	return len(b)
}

func nonEmpty(vals ...string) []string {
	var out []string
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
