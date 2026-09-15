// Package ai implements the Quetzalog AI Analyst: a provider-independent
// service that turns findings into structured, evidence-based analyses with
// a recommended next step. The analyst never executes anything — every
// recommendation is stored and awaits an explicit human decision.
package ai

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Analysis is the validated structured output of a model analysis.
// The model is required to return exactly this shape; anything else is
// rejected and the analysis is marked failed.
type Analysis struct {
	Title                   string            `json:"title"`
	Summary                 string            `json:"summary"`
	Severity                string            `json:"severity"`
	Confidence              float64           `json:"confidence"`
	WhatIsHappening         string            `json:"what_is_happening"`
	WhyItMatters            string            `json:"why_it_matters"`
	Evidence                []string          `json:"evidence"`
	AlternativeExplanations []string          `json:"alternative_explanations"`
	RecommendedAction       RecommendedAction `json:"recommended_action"`
	// Statements is the structured, classified superset of Evidence
	// (spec §32): every statement carries a classification and the refs
	// it came from.
	Statements []Statement `json:"statements,omitempty"`
	// AttackChain is the observed/expected ATT&CK progression.
	AttackChain AttackChain `json:"attack_chain,omitempty"`
	// MitreMapping ties techniques to their evidence.
	MitreMapping []MitreMapEntry `json:"mitre_mapping,omitempty"`
	// Gaps is the explicit "what we do not know" section (spec §78).
	Gaps []string `json:"gaps,omitempty"`
	// RiskAssessment is the optional numeric risk view.
	RiskAssessment *RiskAssessment `json:"risk_assessment,omitempty"`
	// RequiresHumanApproval is a safety invariant: it is forced to true by
	// the validator regardless of what the model returned.
	RequiresHumanApproval bool `json:"requires_human_approval"`
}

// Classifications is the closed set of statement classifications (spec §32).
var Classifications = []string{"OBSERVED", "INFERRED", "HYPOTHESIS", "UNKNOWN"}

// Statement is one classified claim with its provenance refs.
type Statement struct {
	Text           string   `json:"text"`
	Classification string   `json:"classification"`
	EvidenceRefs   []string `json:"evidence_refs,omitempty"`
}

// AttackChain is the model's view of the ATT&CK progression.
type AttackChain struct {
	Observed     []string `json:"observed,omitempty"`
	ExpectedNext []string `json:"expected_next,omitempty"`
	Gaps         []string `json:"gaps,omitempty"`
}

// MitreMapEntry ties one technique/tactic to its evidence refs.
type MitreMapEntry struct {
	Technique   string   `json:"technique"`
	Tactic      string   `json:"tactic,omitempty"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
}

// RiskAssessment is the optional numeric risk view with a ref to the
// supporting assessment.
type RiskAssessment struct {
	Score       int    `json:"score"`
	ReasonsRef  string `json:"reasons_ref,omitempty"`
}

// RecommendedAction is the safest useful next step proposed by the analyst.
// It is a recommendation only — Quetzalog never executes it automatically.
type RecommendedAction struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Risk        string `json:"risk"`
}

// ActionTypes is the closed set of recommendation types the model may use.
// The set is deliberately capability-oriented so the same vocabulary can be
// wired to real Quetzalog actions later without changing stored analyses.
var ActionTypes = []string{
	"investigate",
	"collect_evidence",
	"run_query",
	"create_incident",
	"escalate",
	"remediate",
	"block",
	"quarantine",
	"disable_account",
	"rotate_credentials",
}

// RiskLevels are the allowed risk ratings for a recommended action.
var RiskLevels = []string{"low", "medium", "high"}

// Severity levels accepted in model output (normalized to the SOC scale).
var validSeverities = map[string]string{
	"critical": "critical",
	"high":     "high",
	"medium":   "medium",
	"low":      "low",
}

// Limits bound model output so storage and the UI stay safe.
const (
	maxTitleLen     = 200
	maxSummaryLen   = 2000
	maxTextLen      = 4000
	maxEvidence     = 10
	maxEvidenceLen  = 500
	maxAlternatives = 5
	maxAltLen       = 300
	maxActionDesc   = 600
	maxStatements   = 20
	maxStatementLen = 500
	maxRefs         = 8
	maxRefLen       = 160
	maxGaps         = 10
)

// ErrInvalidResponse marks model output that failed schema validation.
// It carries a human-readable reason safe to show in the UI.
type ErrInvalidResponse struct{ Reason string }

func (e ErrInvalidResponse) Error() string { return "invalid model response: " + e.Reason }

func (e ErrInvalidResponse) Is(target error) bool { _, ok := target.(ErrInvalidResponse); return ok }

// rawAnalysis mirrors Analysis with `any` fields so real model output — which
// occasionally drifts in types (confidence as a string, evidence as a plain
// sentence, ...) — can be normalized before the strict checks apply.
type rawAnalysis struct {
	Title                   any `json:"title"`
	Summary                 any `json:"summary"`
	Severity                any `json:"severity"`
	Confidence              any `json:"confidence"`
	WhatIsHappening         any `json:"what_is_happening"`
	WhyItMatters            any `json:"why_it_matters"`
	Evidence                any `json:"evidence"`
	AlternativeExplanations any `json:"alternative_explanations"`
	RecommendedAction       any `json:"recommended_action"`
	Statements              any `json:"statements"`
	AttackChain             any `json:"attack_chain"`
	MitreMapping            any `json:"mitre_mapping"`
	Gaps                    any `json:"gaps"`
	RiskAssessment          any `json:"risk_assessment"`
}

// ValidateAnalysis parses and validates raw model output without an evidence
// context. It is a convenience wrapper around ValidateAnalysisWithContext:
// statement classifications are still enforced, but provenance cross-checks
// are skipped when no context is supplied.
func ValidateAnalysis(raw []byte) (*Analysis, error) {
	return ValidateAnalysisWithContext(raw, nil)
}

// ValidateAnalysisWithContext parses and validates raw model output against
// the supplied evidence context. It tolerates a single ```json code fence
// around the payload and mild type drift from real models (string
// confidences, percent values, word levels). Statement provenance is
// checked against the context:
//   - every statement must carry a valid classification;
//   - OBSERVED statements must cite ≥1 event id present in the context
//     (or the finding's event ids) — otherwise the analysis is rejected as
//     unsupported_observed_claim;
//   - INFERRED/HYPOTHESIS statements must cite ≥1 known context ref
//     (event, indicator, asset, finding or coverage ref).
//
// On success the returned analysis has normalized severity, clamped
// confidence and a forced RequiresHumanApproval=true.
func ValidateAnalysisWithContext(raw []byte, ctx *FindingContext) (*Analysis, error) {
	txt := strings.TrimSpace(string(raw))
	if i := strings.Index(txt, "```"); i >= 0 {
		// Strip a leading code fence: ```json ... ``` or ``` ... ```
		rest := txt[i+len("```"):]
		if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
			rest = rest[nl+1:]
		}
		if j := strings.LastIndex(rest, "```"); j >= 0 {
			rest = rest[:j]
		}
		txt = strings.TrimSpace(rest)
	}
	start := strings.Index(txt, "{")
	end := strings.LastIndex(txt, "}")
	if start < 0 || end <= start {
		return nil, ErrInvalidResponse{"no JSON object in model output"}
	}

	var r rawAnalysis
	if err := json.Unmarshal([]byte(txt[start:end+1]), &r); err != nil {
		return nil, ErrInvalidResponse{"model output is not valid JSON: " + err.Error()}
	}

	a := &Analysis{}
	a.Title = truncate(asString(r.Title), maxTitleLen)
	if a.Title == "" {
		return nil, ErrInvalidResponse{"missing required field: title"}
	}
	a.Summary = truncate(asString(r.Summary), maxSummaryLen)
	if a.Summary == "" {
		return nil, ErrInvalidResponse{"missing required field: summary"}
	}

	sev, ok := validSeverities[strings.ToLower(strings.TrimSpace(asString(r.Severity)))]
	if !ok {
		return nil, ErrInvalidResponse{fmt.Sprintf("severity %q is not one of critical/high/medium/low", asString(r.Severity))}
	}
	a.Severity = sev

	conf, err := asConfidence(r.Confidence)
	if err != nil {
		return nil, err
	}
	a.Confidence = conf

	a.WhatIsHappening = truncate(asString(r.WhatIsHappening), maxTextLen)
	if strings.TrimSpace(a.WhatIsHappening) == "" {
		return nil, ErrInvalidResponse{"missing required field: what_is_happening"}
	}
	a.WhyItMatters = truncate(asString(r.WhyItMatters), maxTextLen)

	a.Evidence = cleanList(asStringList(r.Evidence), maxEvidence, maxEvidenceLen)
	a.AlternativeExplanations = cleanList(asStringList(r.AlternativeExplanations), maxAlternatives, maxAltLen)

	action, err := asAction(r.RecommendedAction)
	if err != nil {
		return nil, err
	}
	a.RecommendedAction = action

	// Structured v2 sections (additive: absent sections stay nil).
	a.Statements, err = asStatements(r.Statements)
	if err != nil {
		return nil, err
	}
	a.AttackChain = asAttackChain(r.AttackChain)
	a.MitreMapping = asMitreMapping(r.MitreMapping)
	a.Gaps = cleanList(asStringList(r.Gaps), maxGaps, maxAltLen)
	if ra := asRiskAssessment(r.RiskAssessment); ra != nil {
		a.RiskAssessment = ra
	}

	// Provenance cross-check (spec §32, §35): classified claims must cite
	// evidence that exists in the supplied context.
	if ctx != nil {
		if err := checkStatementProvenance(a.Statements, ctx); err != nil {
			return nil, err
		}
	}

	// Safety invariant, regardless of model output.
	a.RequiresHumanApproval = true
	return a, nil
}

// asStatements normalizes the statement list; every statement must carry a
// valid classification (spec §32 — classification is mandatory).
func asStatements(v any) ([]Statement, error) {
	if v == nil {
		return nil, nil
	}
	items, ok := v.([]any)
	if !ok {
		return nil, ErrInvalidResponse{"statements must be a JSON array"}
	}
	out := make([]Statement, 0, len(items))
	for i, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, ErrInvalidResponse{fmt.Sprintf("statement %d is not an object", i)}
		}
		text := truncate(strings.TrimSpace(asString(m["text"])), maxStatementLen)
		if text == "" {
			return nil, ErrInvalidResponse{fmt.Sprintf("statement %d has no text", i)}
		}
		class := strings.ToUpper(strings.TrimSpace(asString(m["classification"])))
		if !contains(Classifications, class) {
			return nil, ErrInvalidResponse{fmt.Sprintf("statement %d classification %q is not one of %s", i, asString(m["classification"]), strings.Join(Classifications, ", "))}
		}
		refs := cleanList(asStringList(m["evidence_refs"]), maxRefs, maxRefLen)
		out = append(out, Statement{Text: text, Classification: class, EvidenceRefs: refs})
		if len(out) == maxStatements {
			break
		}
	}
	return out, nil
}

// asAttackChain normalizes the attack chain; unknown shapes are dropped
// rather than rejected (additive field).
func asAttackChain(v any) AttackChain {
	var chain AttackChain
	m, ok := v.(map[string]any)
	if !ok {
		return chain
	}
	chain.Observed = cleanList(asStringList(m["observed"]), 20, 60)
	chain.ExpectedNext = cleanList(asStringList(m["expected_next"]), 20, 60)
	chain.Gaps = cleanList(asStringList(m["gaps"]), maxGaps, maxAltLen)
	return chain
}

// asMitreMapping normalizes the technique→evidence ties.
func asMitreMapping(v any) []MitreMapEntry {
	if v == nil {
		return nil
	}
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := []MitreMapEntry{}
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		tech := strings.TrimSpace(asString(m["technique"]))
		if tech == "" {
			continue
		}
		out = append(out, MitreMapEntry{
			Technique:    tech,
			Tactic:       strings.TrimSpace(asString(m["tactic"])),
			EvidenceRefs: cleanList(asStringList(m["evidence_refs"]), maxRefs, maxRefLen),
		})
		if len(out) == 20 {
			break
		}
	}
	return out
}

// asRiskAssessment normalizes the risk assessment; score is clamped to 0-100.
func asRiskAssessment(v any) *RiskAssessment {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	var score int
	switch t := m["score"].(type) {
	case float64:
		score = int(t)
	case string:
		score, _ = strconv.Atoi(strings.TrimSpace(t))
	default:
		return nil
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return &RiskAssessment{Score: score, ReasonsRef: truncate(asString(m["reasons_ref"]), 200)}
}

// checkStatementProvenance enforces the §32 provenance rules against the
// evidence context.
func checkStatementProvenance(statements []Statement, ctx *FindingContext) error {
	if len(statements) == 0 {
		return nil
	}
	knownEvents := map[string]bool{}
	knownRefs := map[string]bool{}
	for _, ev := range ctx.Events {
		knownEvents[ev.ID] = true
		knownRefs[ev.ID] = true
	}
	knownRefs[ctx.Finding.ID] = true
	for _, r := range ctx.Related {
		knownRefs[r.ID] = true
	}
	for _, ti := range ctx.ThreatIntel {
		knownRefs[ti.Value] = true
	}
	if ctx.AssetContext != nil {
		for _, h := range ctx.AssetContext.Hosts {
			knownRefs[h.Name] = true
		}
	}
	for _, g := range ctx.TelemetryGaps {
		knownRefs["coverage:"+g] = true
		knownRefs[g] = true
	}

	for i, st := range statements {
		switch st.Classification {
		case "OBSERVED":
			ok := false
			for _, ref := range st.EvidenceRefs {
				if knownEvents[ref] {
					ok = true
					break
				}
			}
			if !ok {
				return ErrInvalidResponse{"unsupported_observed_claim: statement " +
					fmt.Sprintf("%d", i+1) + " cites no event id present in the context"}
			}
		case "INFERRED", "HYPOTHESIS":
			if len(st.EvidenceRefs) == 0 {
				return ErrInvalidResponse{fmt.Sprintf("statement %d (%s) must cite at least one context ref", i+1, st.Classification)}
			}
			for _, ref := range st.EvidenceRefs {
				if !knownRefs[ref] {
					return ErrInvalidResponse{fmt.Sprintf("statement %d cites unknown ref %q", i+1, ref)}
				}
			}
		case "UNKNOWN":
			// Explicit unknowns need no provenance.
		}
	}
	return nil
}

// asString tolerates scalar type drift and never fails.
func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == math.Trunc(t) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return ""
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

// asConfidence normalizes model confidence to a float in [0,1]. Accepted
// forms: JSON numbers in [0,1]; values in (1,100] (interpreted as percent,
// e.g. 82 → 0.82); numeric strings ("0.8", "82%", "82"); and the words
// low/medium/high. Anything else is a validation error.
func asConfidence(v any) (float64, error) {
	switch t := v.(type) {
	case float64:
		return normalizeConfidence(t, "confidence")
	case string:
		s := strings.ToLower(strings.TrimSpace(t))
		if s == "" {
			return 0.5, nil // absent/empty confidence is advisory; default to "unknown"
		}
		switch s {
		case "low":
			return 0.4, nil
		case "medium":
			return 0.6, nil
		case "high":
			return 0.8, nil
		}
		if strings.HasSuffix(s, "%") {
			s = strings.TrimSuffix(strings.TrimSpace(s), "%")
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return 0, ErrInvalidResponse{fmt.Sprintf("confidence %q is not a number in [0,1]", t)}
		}
		return normalizeConfidence(f, fmt.Sprintf("confidence %q", t))
	case nil:
		return 0.5, nil
	default:
		return 0, ErrInvalidResponse{fmt.Sprintf("unsupported confidence type %T", v)}
	}
}

func normalizeConfidence(f float64, label string) (float64, error) {
	switch {
	case f >= 0 && f <= 1:
	case f > 1 && f <= 100:
		f = f / 100 // percent scale
	default:
		return 0, ErrInvalidResponse{fmt.Sprintf("%s is outside [0,100] after percent normalization", label)}
	}
	return float64(int(f*100+0.5)) / 100, nil
}

// asStringList accepts an array of scalars or a single scalar.
func asStringList(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s := asString(x); strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if strings.TrimSpace(t) == "" {
			return nil
		}
		return []string{t}
	case nil:
		return nil
	default:
		return []string{asString(v)}
	}
}

// asAction normalizes the recommended action; its type stays in the closed
// set because an unknown type must never map to a capability the system does
// not have.
func asAction(v any) (RecommendedAction, error) {
	var m map[string]any
	switch t := v.(type) {
	case map[string]any:
		m = t
	case string:
		// Some models return a bare sentence for the action. Record it with
		// the safest default type — the operator reads the description and
		// approves before anything happens.
		if s := strings.TrimSpace(t); s != "" {
			return RecommendedAction{
				Type:        "investigate",
				Description: truncate(s, maxActionDesc),
				Risk:        "medium",
			}, nil
		}
		return RecommendedAction{}, ErrInvalidResponse{"recommended_action must not be empty"}
	default:
		return RecommendedAction{}, ErrInvalidResponse{"missing required field: recommended_action"}
	}

	act := RecommendedAction{
		Type:        strings.ToLower(strings.TrimSpace(asString(m["type"]))),
		Description: truncate(asString(m["description"]), maxActionDesc),
		Risk:        strings.ToLower(strings.TrimSpace(asString(m["risk"]))),
	}
	if act.Type != "" {
		act.Type = strings.ReplaceAll(act.Type, " ", "_")
	}
	if !contains(ActionTypes, act.Type) {
		return RecommendedAction{}, ErrInvalidResponse{fmt.Sprintf("recommended action type %q is not allowed (expected one of %s)", m["type"], strings.Join(ActionTypes, ", "))}
	}
	if strings.TrimSpace(act.Description) == "" {
		return RecommendedAction{}, ErrInvalidResponse{"missing required field: recommended_action.description"}
	}
	if !contains(RiskLevels, act.Risk) || act.Risk == "" {
		act.Risk = "medium"
	}
	return act, nil
}

func truncate(s string, maxRunes int) string {
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	r := []rune(s)
	return string(r[:maxRunes]) + "…"
}

func cleanList(in []string, maxItems, maxLen int) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		out = append(out, truncate(s, maxLen))
		if len(out) == maxItems {
			break
		}
	}
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
