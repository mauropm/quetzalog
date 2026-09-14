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
	// RequiresHumanApproval is a safety invariant: it is forced to true by
	// the validator regardless of what the model returned.
	RequiresHumanApproval bool `json:"requires_human_approval"`
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
}

// ValidateAnalysis parses and validates raw model output. It tolerates a
// single ```json code fence around the payload and mild type drift from
// real models (string confidences, percent values, word levels). On success
// the returned analysis has normalized severity, clamped confidence and a
// forced RequiresHumanApproval=true.
func ValidateAnalysis(raw []byte) (*Analysis, error) {
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

	// Safety invariant, regardless of model output.
	a.RequiresHumanApproval = true
	return a, nil
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
