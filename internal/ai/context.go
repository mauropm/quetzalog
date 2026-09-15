package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"quetzalog/internal/events"
	"quetzalog/internal/findings"
	"quetzalog/pkg/event"
)

// maxContextJSONBytes bounds the serialized evidence snapshot. The context
// is deliberately compact: the model receives structured facts, never raw
// log floods.
const maxContextJSONBytes = 48 * 1024

// maxEventMessage trims individual event messages to keep the context tight.
const maxEventMessage = 240

// maxContextHosts bounds how many of the finding's hosts get asset/coverage
// lookups in the context.
const maxContextHosts = 3

// maxTIHits bounds threat-intel entries included in the context.
const maxTIHits = 10

// maxPriorAnalyses bounds the operator-feedback section.
const maxPriorAnalyses = 5

// FindingContext is the structured evidence snapshot sent to the model
// (ai-security-analysis.md §1). Every section is a bounded query result and
// carries the ids its facts came from; the model must cite them.
// No credentials or configuration data are included — untrusted text is
// redacted before the context is serialized.
type FindingContext struct {
	Finding   FindingInfo     `json:"finding"`
	Events    []EventInfo     `json:"events"`
	Related   []FindingInfo   `json:"related_findings"`
	Entities  EntitySummary   `json:"entities"`
	AssetContext *AssetContext `json:"asset_context,omitempty"`
	ThreatIntel  []TIHit      `json:"threat_intel,omitempty"`
	Mitre        *MitreContext  `json:"mitre_context,omitempty"`
	AttackGraph  *AttackGraphBrief `json:"attack_graph,omitempty"`
	TelemetryGaps []string     `json:"telemetry_gaps,omitempty"`
	PriorAnalyses []PriorAnalysis `json:"prior_analyses,omitempty"`
}

// UnmarshalJSON tolerates legacy v1 context rows, whose telemetry_gaps were
// objects and which had a flat "assets" list. Those fields are dropped
// before the strict decode so stored contexts remain readable.
func (c *FindingContext) UnmarshalJSON(b []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err == nil {
		if raw, ok := m["telemetry_gaps"]; ok {
			var probe []string
			if json.Unmarshal(raw, &probe) != nil {
				delete(m, "telemetry_gaps")
			}
		}
		if raw, ok := m["assets"]; ok {
			var probe []map[string]any
			if json.Unmarshal(raw, &probe) != nil {
				delete(m, "assets")
			}
		}
		if len(m) > 0 {
			if scrubbed, err := json.Marshal(m); err == nil {
				b = scrubbed
			}
		}
	}
	type alias FindingContext
	return json.Unmarshal(b, (*alias)(c))
}

// AssetContext is the bounded asset view around the finding's hosts.
type AssetContext struct {
	Hosts []HostAsset `json:"hosts,omitempty"`
}

// HostAsset is one asset with its criticality, telemetry coverage and
// linked vulnerabilities.
type HostAsset struct {
	Name               string        `json:"name"`
	EntityType         string        `json:"entity_type,omitempty"`
	OS                 string        `json:"os,omitempty"`
	Criticality        string        `json:"criticality,omitempty"`
	Owner              string        `json:"owner,omitempty"`
	Environment        string        `json:"environment,omitempty"`
	InternetExposed    bool          `json:"internet_exposed"`
	DataClassification string        `json:"data_classification,omitempty"`
	TelemetryCoverage  *CoveragePct  `json:"telemetry_coverage,omitempty"`
	Vulnerabilities    []VulnBrief   `json:"vulnerabilities,omitempty"`
}

// CoveragePct is a compact telemetry-coverage snapshot.
type CoveragePct struct {
	Pct     float64  `json:"pct"`
	Missing []string `json:"missing,omitempty"`
}

// VulnBrief is one CVE linked to an asset.
type VulnBrief struct {
	CVE              string   `json:"cve"`
	CVSS             *float64 `json:"cvss,omitempty"`
	ExploitAvailable string   `json:"exploit_available,omitempty"`
}

// TIHit is one threat-intel entry for a context value, with its confidence
// composition and attribution.
type TIHit struct {
	Value        string    `json:"value"`
	Type         string    `json:"type"`
	Severity     string    `json:"severity,omitempty"`
	Description  string    `json:"description,omitempty"`
	Source       string    `json:"source,omitempty"`
	Confidence   TIConfidence `json:"confidence"`
	Actors       []string  `json:"actors,omitempty"`
	Malware      []string  `json:"malware,omitempty"`
	FirstSeen    time.Time `json:"first_seen,omitempty"`
	LastSeen     time.Time `json:"last_seen,omitempty"`
	References   []string  `json:"references,omitempty"`
}

// TIConfidence mirrors the threat-intel confidence composition.
type TIConfidence struct {
	SourceReliability  float64 `json:"source_reliability"`
	IndicatorConfidence float64 `json:"indicator_confidence"`
	Corroboration      int     `json:"corroboration"`
}

// MitreContext is the observed ATT&CK position of the finding.
type MitreContext struct {
	Observed          []ObservedTechnique `json:"observed_techniques"`
	KillChainPosition string              `json:"kill_chain_position,omitempty"`
	ScenarioRun       *ScenarioBrief      `json:"scenario_run,omitempty"`
}

// ObservedTechnique is a mapped technique with the event ids it came from.
type ObservedTechnique struct {
	ID             string   `json:"id"`
	Name           string   `json:"name,omitempty"`
	Tactic         string   `json:"tactic,omitempty"`
	EvidenceEvents []string `json:"evidence_events"`
}

// ScenarioBrief summarizes one active scenario run for the finding's host.
type ScenarioBrief struct {
	Name         string    `json:"name"`
	Status       string    `json:"status,omitempty"`
	OpenedAt     time.Time `json:"opened_at,omitempty"`
	Observed     []string  `json:"observed,omitempty"`
	ExpectedNext []string  `json:"expected_next,omitempty"`
	Unknown      []string  `json:"unknown,omitempty"`
}

// AttackGraphBrief is the bounded, state-labeled neighborhood of the
// finding's hosts in the attack graph.
type AttackGraphBrief struct {
	CompromisedNodes []string    `json:"compromised_nodes,omitempty"`
	AtRiskNodes      []string    `json:"at_risk_nodes,omitempty"`
	Edges            []GraphEdge `json:"edges,omitempty"`
}

// GraphEdge is one relationship with its compromise state.
type GraphEdge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Relation string `json:"relation"`
	State    string `json:"state,omitempty"`
}

// PriorAnalysis is one earlier analysis with the operator's decision —
// the feedback loop (spec §33): FP decisions are visible to the model.
type PriorAnalysis struct {
	ID        string `json:"id"`
	FindingID string `json:"finding_id,omitempty"`
	Summary   string `json:"summary,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Decision  string `json:"decision"`
	Reason    string `json:"reason,omitempty"`
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

// EventInfo is a compact event representation with provenance.
type EventInfo struct {
	ID        string      `json:"id"`
	Timestamp time.Time   `json:"timestamp"`
	Severity  string      `json:"severity"`
	Source    string      `json:"source,omitempty"`
	Host      string      `json:"host,omitempty"`
	User      string      `json:"user,omitempty"`
	Message   string      `json:"message"`
	EventType string      `json:"event_type,omitempty"`
	Category  string      `json:"category,omitempty"`
	Action    string      `json:"action,omitempty"`
	Outcome   string      `json:"outcome,omitempty"`
	Entities  []string    `json:"entities,omitempty"`
	Mitre     []MitreHit  `json:"mitre,omitempty"`
}

// MitreHit is one ATT&CK mapping carried on an event.
type MitreHit struct {
	Technique string  `json:"technique"`
	Name      string  `json:"name,omitempty"`
	Tactic    string  `json:"tactic,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

// EntitySummary groups the entities involved in the finding.
type EntitySummary struct {
	IPs       []string `json:"ip_addresses,omitempty"`
	Users     []string `json:"users,omitempty"`
	Hosts     []string `json:"hosts,omitempty"`
	Sources   []string `json:"sources,omitempty"`
	Processes []string `json:"processes,omitempty"`
	Domains   []string `json:"domains,omitempty"`
	Files     []string `json:"files,omitempty"`
	Hashes    []string `json:"hashes,omitempty"`
}

// ContextBuilder assembles the analyst context from a finding. Optional
// lookups (assets, threat intel, scenarios, attack graph, prior analyses)
// are wired via hooks; when unset, the corresponding section is omitted.
// Untrusted text is redacted before serialization.
type ContextBuilder struct {
	findings    *findings.Store
	events      *events.Store
	logger      *slog.Logger
	assetFor    func(ctx context.Context, host string) *HostAsset
	tiFor       func(ctx context.Context, values []string) []TIHit
	scenarioFor func(ctx context.Context, host string) *ScenarioBrief
	graphFor    func(ctx context.Context, hosts []string) *AttackGraphBrief
	analysesFor func(ctx context.Context, findingIDs []string) []PriorAnalysis
}

// NewContextBuilder creates a context builder over the finding and event stores.
func NewContextBuilder(findings *findings.Store, evStore *events.Store) *ContextBuilder {
	return &ContextBuilder{findings: findings, events: evStore}
}

// WithLogger sets the logger used for redaction records.
func (b *ContextBuilder) WithLogger(l *slog.Logger) *ContextBuilder {
	b.logger = l
	return b
}

// WithAssets adds an asset-enrichment lookup for the finding's hosts
// (criticality, coverage, vulnerabilities). Nil-safe.
func (b *ContextBuilder) WithAssets(fn func(ctx context.Context, host string) *HostAsset) *ContextBuilder {
	b.assetFor = fn
	return b
}

// WithThreatIntel adds an indicator lookup for the context's values. Nil-safe.
func (b *ContextBuilder) WithThreatIntel(fn func(ctx context.Context, values []string) []TIHit) *ContextBuilder {
	b.tiFor = fn
	return b
}

// WithScenarios adds an active-scenario lookup for a host. Nil-safe.
func (b *ContextBuilder) WithScenarios(fn func(ctx context.Context, host string) *ScenarioBrief) *ContextBuilder {
	b.scenarioFor = fn
	return b
}

// WithAttackGraph adds the bounded attack-graph neighborhood lookup. Nil-safe.
func (b *ContextBuilder) WithAttackGraph(fn func(ctx context.Context, hosts []string) *AttackGraphBrief) *ContextBuilder {
	b.graphFor = fn
	return b
}

// WithPriorAnalyses adds the operator-feedback lookup. Nil-safe.
func (b *ContextBuilder) WithPriorAnalyses(fn func(ctx context.Context, findingIDs []string) []PriorAnalysis) *ContextBuilder {
	b.analysesFor = fn
	return b
}

// Build collects the finding's events (bounded), related findings, entities,
// and the wired context sections. maxEvents <= 0 falls back to 100.
func (b *ContextBuilder) Build(ctx context.Context, f *findings.Finding, maxEvents int) (*FindingContext, error) {
	if f == nil {
		return nil, fmt.Errorf("nil finding")
	}
	if maxEvents <= 0 {
		maxEvents = 100
	}

	fctx := &FindingContext{
		Finding: FindingInfo{
			ID:             f.ID,
			Title:          f.Title,
			Description:    truncate(f.Description, 500),
			Severity:       f.Severity,
			Status:         f.Status,
			DetectionName:  f.DetectionName,
			MITRETactic:    f.MITRETactic,
			MITRETechnique: f.MITRETechnique,
			MatchCount:     f.MatchCount,
			FirstSeen:      f.FirstSeen,
			LastSeen:       f.LastSeen,
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
		info := EventInfo{
			ID:        ev.ID,
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
			Entities:  eventEntities(ev),
			Mitre:     eventMitre(ev),
		}
		// Redaction pass: untrusted text becomes marked placeholders.
		if msg, fired := RedactText(info.Message); len(fired) > 0 {
			info.Message = msg
			logRedaction(b.logger, "event:"+ev.ID, fired)
		}
		if user, fired := RedactText(info.User); len(fired) > 0 {
			info.User = user
			logRedaction(b.logger, "event.user:"+ev.ID, fired)
		}
		fctx.Events = append(fctx.Events, info)
	}

	// Related findings through shared entities.
	seen := map[string]bool{f.ID: true}
	relatedIDs := []string{f.ID}
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
			relatedIDs = append(relatedIDs, r.ID)
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

	// Entity summary (depth-1: finding fields + event fields/attributes).
	sum := &fctx.Entities
	sum.IPs = append(sum.IPs, nonEmpty(f.SourceIP, f.DestinationIP)...)
	sum.Users = append(sum.Users, f.User)
	sum.Hosts = append(sum.Hosts, f.Host)
	for _, ent := range f.Entities {
		addEntity(sum, ent)
	}
	for _, ev := range fctx.Events {
		for _, e := range ev.Entities {
			addEntity(sum, e)
		}
		sum.Sources = append(sum.Sources, ev.Source)
	}
	fctx.Entities = EntitySummary{
		IPs:       unique(sum.IPs),
		Users:     unique(sum.Users),
		Hosts:     unique(sum.Hosts),
		Sources:   unique(sum.Sources),
		Processes: unique(sum.Processes),
		Domains:   unique(sum.Domains),
		Files:     unique(sum.Files),
		Hashes:    unique(sum.Hashes),
	}

	// Hosts get asset enrichment (bounded to a few hosts).
	hosts := fctx.Entities.Hosts
	if len(hosts) > maxContextHosts {
		hosts = hosts[:maxContextHosts]
	}
	if b.assetFor != nil && len(hosts) > 0 {
		ac := &AssetContext{}
		for _, host := range hosts {
			a := b.assetFor(ctx, host)
			if a == nil {
				continue
			}
			ac.Hosts = append(ac.Hosts, *a)
			if a.TelemetryCoverage != nil {
				for _, m := range a.TelemetryCoverage.Missing {
					fctx.TelemetryGaps = append(fctx.TelemetryGaps,
						fmt.Sprintf("%s on %s — no telemetry; activity of this kind: unknown", m, a.Name))
				}
			}
		}
		if len(ac.Hosts) > 0 {
			fctx.AssetContext = ac
		}
	}

	// Threat intel for the context's values (bounded).
	if b.tiFor != nil {
		values := make([]string, 0, 8)
		values = append(values, fctx.Entities.IPs...)
		values = append(values, fctx.Entities.Domains...)
		values = append(values, fctx.Entities.Hashes...)
		if v := nonEmpty(f.SourceIP, f.DestinationIP); len(v) > 0 {
			values = append(values, v...)
		}
		values = unique(values)
		if len(values) > 0 {
			hits := b.tiFor(ctx, values)
			for i := range hits {
				desc, fired := RedactText(hits[i].Description)
				if len(fired) > 0 {
					logRedaction(b.logger, "ti:"+hits[i].Value, fired)
				}
				hits[i].Description = truncate(desc, 300)
			}
			if len(hits) > maxTIHits {
				hits = hits[:maxTIHits]
			}
			fctx.ThreatIntel = hits
		}
	}

	// MITRE context: observed techniques + kill-chain position + scenario.
	mitre, hasMitre := mitreContext(fctx.Events, f.MITRETactic)
	if b.scenarioFor != nil && len(hosts) > 0 {
		if sb := b.scenarioFor(ctx, hosts[0]); sb != nil {
			if mitre == nil {
				mitre = &MitreContext{}
			}
			mitre.ScenarioRun = sb
			hasMitre = true
		}
	}
	if hasMitre {
		fctx.Mitre = mitre
	}

	// Attack graph neighborhood (bounded).
	if b.graphFor != nil && len(hosts) > 0 {
		if g := b.graphFor(ctx, hosts); g != nil &&
			(len(g.CompromisedNodes) > 0 || len(g.AtRiskNodes) > 0 || len(g.Edges) > 0) {
			fctx.AttackGraph = g
		}
	}

	// Operator feedback: prior analyses with decisions.
	if b.analysesFor != nil && len(relatedIDs) > 0 {
		prior := b.analysesFor(ctx, relatedIDs)
		if len(prior) > maxPriorAnalyses {
			prior = prior[:maxPriorAnalyses]
		}
		fctx.PriorAnalyses = prior
	}

	// Enforce the context size budget: drop oldest events first, then shrink
	// related findings (spec §1).
	for i := 0; i < 40; i++ {
		if fctx.jsonSize() <= maxContextJSONBytes {
			break
		}
		if len(fctx.Events) > 0 {
			fctx.Events = fctx.Events[1:]
			continue
		}
		if len(fctx.Related) > 0 {
			fctx.Related = fctx.Related[1:]
			continue
		}
		if len(fctx.ThreatIntel) > 0 {
			fctx.ThreatIntel = fctx.ThreatIntel[1:]
			continue
		}
		break
	}
	return fctx, nil
}

// addEntity routes a "type:value" entity ref into the summary buckets.
func addEntity(sum *EntitySummary, ent string) {
	parts := strings.SplitN(ent, ":", 2)
	if len(parts) != 2 || parts[1] == "" {
		return
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
	case "domain":
		sum.Domains = append(sum.Domains, parts[1])
	case "file":
		sum.Files = append(sum.Files, parts[1])
	case "hash", "sha256", "md5", "sha1":
		sum.Hashes = append(sum.Hashes, parts[1])
	}
}

// eventEntities extracts the bounded, citable entity refs from one event.
func eventEntities(ev *event.Event) []string {
	var out []string
	if ev.IP != "" {
		out = append(out, "ip:"+ev.IP)
	}
	if ev.SourceIP != "" {
		out = append(out, "ip:"+ev.SourceIP)
	}
	if ev.DestinationIP != "" {
		out = append(out, "ip:"+ev.DestinationIP)
	}
	if ev.Host != "" {
		out = append(out, "host:"+ev.Host)
	}
	if ev.User != "" {
		out = append(out, "user:"+ev.User)
	}
	if ev.Process != "" {
		out = append(out, "process:"+ev.Process)
	}
	if ev.FilePath != "" {
		out = append(out, "file:"+ev.FilePath)
	}
	// Attribute-derived depth-1 entities.
	for _, key := range []string{"domain", "destination_domain", "dns.query", "url"} {
		if v, ok := ev.Attributes[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				out = append(out, "domain:"+s)
			}
		}
	}
	for _, key := range []string{"hash", "sha256", "md5", "sha1"} {
		if v, ok := ev.Attributes[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				out = append(out, "hash:"+s)
			}
		}
	}
	return out
}

// eventMitre decodes the mitre.attack event attribute (written by the
// event mapper). Absent/invalid mappings are omitted, never fatal.
func eventMitre(ev *event.Event) []MitreHit {
	mitre, ok := ev.Attributes["mitre"]
	if !ok {
		return nil
	}
	atk, ok := mitre.(map[string]any)
	if !ok {
		return nil
	}
	raw, ok := atk["attack"].([]any)
	if !ok {
		return nil
	}
	out := []MitreHit{}
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		h := MitreHit{}
		if s, ok := m["technique"].(string); ok {
			h.Technique = s
		}
		if s, ok := m["technique_name"].(string); ok {
			h.Name = s
		}
		if s, ok := m["tactic"].(string); ok {
			h.Tactic = s
		}
		if c, ok := m["confidence"].(float64); ok {
			h.Confidence = c
		}
		if h.Technique != "" {
			out = append(out, h)
		}
	}
	return out
}

// mitreContext aggregates observed techniques across the context events and
// derives the kill-chain position (dominant tactic; falls back to the
// finding's mapped tactic).
func mitreContext(events []EventInfo, findingTactic string) (*MitreContext, bool) {
	byID := map[string]*ObservedTechnique{}
	tacticCount := map[string]int{}
	order := []string{}
	for _, ev := range events {
		for _, h := range ev.Mitre {
			if h.Technique == "" {
				continue
			}
			t, ok := byID[h.Technique]
			if !ok {
				t = &ObservedTechnique{ID: h.Technique, Name: h.Name, Tactic: h.Tactic}
				byID[h.Technique] = t
				order = append(order, h.Technique)
			}
			t.EvidenceEvents = append(t.EvidenceEvents, ev.ID)
			if h.Tactic != "" {
				tacticCount[h.Tactic]++
			}
		}
	}
	if len(byID) == 0 && findingTactic == "" {
		return nil, false
	}
	mc := &MitreContext{}
	for _, id := range order {
		mc.Observed = append(mc.Observed, *byID[id])
	}
	if findingTactic != "" {
		mc.KillChainPosition = findingTactic
	}
	for tactic, n := range tacticCount {
		if mc.KillChainPosition == "" || n > tacticCount[mc.KillChainPosition] {
			mc.KillChainPosition = tactic
		}
	}
	return mc, true
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
