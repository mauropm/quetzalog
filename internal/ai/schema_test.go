package ai

import (
	"errors"
	"strings"
	"testing"
)

func validAnalysisJSON() string {
	return `{
		"title": "Possible credential stuffing attack",
		"summary": "Multiple failed authentication attempts were followed by a successful login from the same source.",
		"severity": "high",
		"confidence": 0.87,
		"what_is_happening": "17 failed logins followed by a successful login from the same source IP.",
		"why_it_matters": "A successful authentication after repeated failures is a strong indicator of account compromise.",
		"evidence": [
			"17 failed authentication attempts within 4 minutes",
			"1 successful login from the same source IP",
			"same source IP across all events"
		],
		"alternative_explanations": [
			"Legitimate user repeatedly entering an incorrect password"
		],
		"recommended_action": {
			"type": "investigate",
			"description": "Review the successful login and determine whether the source IP is trusted.",
			"risk": "low"
		},
		"requires_human_approval": false
	}`
}

func TestValidateAnalysisValid(t *testing.T) {
	a, err := ValidateAnalysis([]byte(validAnalysisJSON()))
	if err != nil {
		t.Fatalf("valid analysis rejected: %v", err)
	}
	if a.Title == "" || a.Summary == "" || a.WhatIsHappening == "" {
		t.Errorf("required text fields empty: %+v", a)
	}
	if a.Severity != "high" {
		t.Errorf("severity: %q", a.Severity)
	}
	if a.Confidence < 0.86 || a.Confidence > 0.88 {
		t.Errorf("confidence not preserved/clamped: %v", a.Confidence)
	}
	if len(a.Evidence) != 3 {
		t.Errorf("evidence count: %d", len(a.Evidence))
	}
	if a.RecommendedAction.Type != "investigate" || a.RecommendedAction.Risk != "low" {
		t.Errorf("recommended action: %+v", a.RecommendedAction)
	}
	// Safety invariant: the model said false, the system must force true.
	if !a.RequiresHumanApproval {
		t.Error("requires_human_approval must be forced to true regardless of model output")
	}
}

func TestValidateAnalysisToleratesCodeFence(t *testing.T) {
	a, err := ValidateAnalysis([]byte("Here is the analysis:\n```json\n" + validAnalysisJSON() + "\n```\n"))
	if err != nil {
		t.Fatalf("fenced analysis rejected: %v", err)
	}
	if a.Severity != "high" {
		t.Errorf("severity: %q", a.Severity)
	}
}

func TestValidateAnalysisMalformedJSON(t *testing.T) {
	_, err := ValidateAnalysis([]byte("I think this is a credential attack. Block the IP!"))
	if err == nil {
		t.Fatal("non-JSON output must be rejected")
	}
	if !errors.As(err, &ErrInvalidResponse{}) {
		t.Errorf("expected ErrInvalidResponse, got %v", err)
	}
}

func TestValidateAnalysisBrokenJSON(t *testing.T) {
	_, err := ValidateAnalysis([]byte(`{"title": "x", "severity":`))
	if err == nil {
		t.Fatal("broken JSON must be rejected")
	}
}

func TestValidateAnalysisMissingRequiredFields(t *testing.T) {
	cases := map[string]string{
		"missing title":     `{"summary":"s","severity":"high","confidence":0.5,"what_is_happening":"w","why_it_matters":"y","recommended_action":{"type":"investigate","description":"d"}}`,
		"missing summary":   `{"title":"t","severity":"high","confidence":0.5,"what_is_happening":"w","why_it_matters":"y","recommended_action":{"type":"investigate","description":"d"}}`,
		"missing happening": `{"title":"t","summary":"s","severity":"high","confidence":0.5,"why_it_matters":"y","recommended_action":{"type":"investigate","description":"d"}}`,
		"missing action":    `{"title":"t","summary":"s","severity":"high","confidence":0.5,"what_is_happening":"w","why_it_matters":"y"}`,
	}
	for name, in := range cases {
		if _, err := ValidateAnalysis([]byte(in)); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

func TestValidateAnalysisInvalidSeverity(t *testing.T) {
	_, err := ValidateAnalysis([]byte(strings.Replace(validAnalysisJSON(), `"severity": "high"`, `"severity": "apocalyptic"`, 1)))
	if err == nil {
		t.Fatal("invalid severity must be rejected")
	}
}

func TestValidateAnalysisInvalidConfidence(t *testing.T) {
	for _, c := range []string{`"confidence": 105`, `"confidence": -0.2`, `"confidence": "very sure"`} {
		_, err := ValidateAnalysis([]byte(strings.Replace(validAnalysisJSON(), `"confidence": 0.87`, c, 1)))
		if err == nil {
			t.Errorf("confidence %s must be rejected", c)
		}
	}
}

// Real models drift in types: string confidences, percent scales, word
// levels, single-string evidence. All must normalize cleanly.
func TestValidateAnalysisTypeDrift(t *testing.T) {
	cases := []struct {
		conf string
		want float64
	}{
		{`"0.8"`, 0.8},  // string decimal
		{`"82%"`, 0.82}, // percent string
		{`"82"`, 0.82},  // bare number string → percent
		{`82`, 0.82},    // JSON number on the percent scale
		{`"high"`, 0.8}, // word level
		{`"low"`, 0.4},  // word level
		{`null`, 0.5},   // missing/empty → advisory default
	}
	for _, c := range cases {
		in := strings.Replace(validAnalysisJSON(), `"confidence": 0.87`, `"confidence": `+c.conf, 1)
		a, err := ValidateAnalysis([]byte(in))
		if err != nil {
			t.Errorf("confidence %s must be accepted: %v", c.conf, err)
			continue
		}
		if a.Confidence != c.want {
			t.Errorf("confidence %s = %v, want %v", c.conf, a.Confidence, c.want)
		}
	}
}

func TestValidateAnalysisEvidenceAsString(t *testing.T) {
	in := strings.Replace(validAnalysisJSON(),
		`"evidence": [
			"17 failed authentication attempts within 4 minutes",
			"1 successful login from the same source IP",
			"same source IP across all events"
		]`,
		`"evidence": "17 failed logins followed by a success from one source"`, 1)
	a, err := ValidateAnalysis([]byte(in))
	if err != nil {
		t.Fatalf("string evidence rejected: %v", err)
	}
	if len(a.Evidence) != 1 {
		t.Errorf("evidence: %#v", a.Evidence)
	}
}

func TestValidateAnalysisActionAsSentenceNormalized(t *testing.T) {
	in := strings.Replace(validAnalysisJSON(),
		`"recommended_action": {
			"type": "investigate",
			"description": "Review the successful login and determine whether the source IP is trusted.",
			"risk": "low"
		}`,
		`"recommended_action": "Review the successful login session first."`, 1)
	a, err := ValidateAnalysis([]byte(in))
	if err != nil {
		t.Fatalf("bare-sentence action must be accepted: %v", err)
	}
	// The type must land in the closed set — mapped to the safest default.
	if a.RecommendedAction.Type != "investigate" {
		t.Errorf("default type: %q", a.RecommendedAction.Type)
	}
	if a.RecommendedAction.Description == "" {
		t.Error("description lost")
	}
	if a.RecommendedAction.Risk != "medium" {
		t.Errorf("default risk: %q", a.RecommendedAction.Risk)
	}
}

func TestValidateAnalysisActionWrongTypeStillRejected(t *testing.T) {
	in := strings.Replace(validAnalysisJSON(),
		`"recommended_action": {
			"type": "investigate",
			"description": "Review the successful login and determine whether the source IP is trusted.",
			"risk": "low"
		}`,
		`"recommended_action": 42`, 1)
	if _, err := ValidateAnalysis([]byte(in)); err == nil {
		t.Error("non-object, non-string action must be rejected")
	}
}

func TestValidateAnalysisHallucinatedActionType(t *testing.T) {
	_, err := ValidateAnalysis([]byte(strings.Replace(validAnalysisJSON(), `"type": "investigate"`, `"type": "launch_nuke"`, 1)))
	if err == nil {
		t.Fatal("unknown action type must be rejected — model output can never trigger an unknown capability")
	}
	if !errors.As(err, &ErrInvalidResponse{}) {
		t.Errorf("expected ErrInvalidResponse, got %v", err)
	}
}

func TestValidateAnalysisActionTypeNormalization(t *testing.T) {
	a, err := ValidateAnalysis([]byte(strings.Replace(validAnalysisJSON(), `"type": "investigate"`, `"type": "Collect Evidence"`, 1)))
	if err != nil {
		t.Fatalf("normalized action type rejected: %v", err)
	}
	if a.RecommendedAction.Type != "collect_evidence" {
		t.Errorf("type: %q", a.RecommendedAction.Type)
	}
}

func TestValidateAnalysisUnknownRiskDefaults(t *testing.T) {
	a, err := ValidateAnalysis([]byte(strings.Replace(validAnalysisJSON(), `"risk": "low"`, `"risk": "existential"`, 1)))
	if err != nil {
		t.Fatalf("unknown risk rejected: %v", err)
	}
	if a.RecommendedAction.Risk != "medium" {
		t.Errorf("risk should default to medium, got %q", a.RecommendedAction.Risk)
	}
}

func TestValidateAnalysisLengthCaps(t *testing.T) {
	long := strings.Repeat("x", 5000)
	in := strings.Replace(validAnalysisJSON(), `"title": "Possible credential stuffing attack"`, `"title": "`+long+`"`, 1)
	a, err := ValidateAnalysis([]byte(in))
	if err != nil {
		t.Fatalf("long title rejected: %v", err)
	}
	if len(a.Title) > 210 {
		t.Errorf("title not capped: %d", len(a.Title))
	}
}
