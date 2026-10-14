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

// ─────────────────────────────────────────────
// Output schema v2: classified statements + provenance (spec §32)
// ─────────────────────────────────────────────

func v2AnalysisJSON() string {
	return `{
		"title": "PowerShell execution on WORKSTATION-42",
		"summary": "Encoded PowerShell executed on WORKSTATION-42 and contacted a known-bad IP.",
		"severity": "critical",
		"confidence": 0.82,
		"what_is_happening": "Encoded PowerShell ran and made outbound contact.",
		"why_it_matters": "Possible C2 beaconing from a production workstation.",
		"evidence": ["Encoded PowerShell on WORKSTATION-42"],
		"alternative_explanations": ["Admin scripting"],
		"recommended_action": {"type": "investigate", "description": "Pivot on the destination IP.", "risk": "low"},
		"statements": [
			{"text": "Encoded PowerShell executed on WORKSTATION-42", "classification": "OBSERVED", "evidence_refs": ["e-98421"]},
			{"text": "PowerShell contacted 203.0.113.50", "classification": "OBSERVED", "evidence_refs": ["e-98422"]},
			{"text": "The destination is associated with suspicious infrastructure", "classification": "INFERRED", "evidence_refs": ["203.0.113.50"]},
			{"text": "The activity may represent command-and-control", "classification": "HYPOTHESIS", "evidence_refs": ["e-98422", "203.0.113.50"]},
			{"text": "Whether credentials were accessed", "classification": "UNKNOWN", "evidence_refs": []}
		],
		"attack_chain": {"observed": ["T1059.001"], "expected_next": ["T1041"], "gaps": ["T1021 unknown — no SMB telemetry"]},
		"mitre_mapping": [{"technique": "T1059.001", "tactic": "TA0002", "evidence_refs": ["e-98421"]}],
		"gaps": ["No DNS telemetry for WORKSTATION-42; C2 via DNS cannot be excluded"],
		"risk_assessment": {"score": 87, "reasons_ref": "finding:f-1/risk"},
		"requires_human_approval": true
	}`
}

func v2Context() *FindingContext {
	return &FindingContext{
		Finding: FindingInfo{ID: "f-1", Title: "PS exec", Severity: "critical", Status: "new"},
		Events: []EventInfo{
			{ID: "e-98421", Host: "WORKSTATION-42"},
			{ID: "e-98422", Host: "WORKSTATION-42"},
		},
		ThreatIntel: []TIHit{{Value: "203.0.113.50", Type: "ip"}},
		TelemetryGaps: []string{"os.windows.dns on WORKSTATION-42 — no telemetry; activity of this kind: unknown"},
	}
}

func TestValidateStatementsValid(t *testing.T) {
	a, err := ValidateAnalysisWithContext([]byte(v2AnalysisJSON()), v2Context())
	if err != nil {
		t.Fatalf("v2 analysis rejected: %v", err)
	}
	if len(a.Statements) != 5 {
		t.Errorf("statements: %d", len(a.Statements))
	}
	if a.Statements[0].Classification != "OBSERVED" || a.Statements[2].Classification != "INFERRED" ||
		a.Statements[3].Classification != "HYPOTHESIS" || a.Statements[4].Classification != "UNKNOWN" {
		t.Errorf("classifications: %+v", a.Statements)
	}
	if len(a.AttackChain.Observed) != 1 || len(a.AttackChain.ExpectedNext) != 1 {
		t.Errorf("attack_chain: %+v", a.AttackChain)
	}
	if len(a.MitreMapping) != 1 || a.MitreMapping[0].Technique != "T1059.001" {
		t.Errorf("mitre_mapping: %+v", a.MitreMapping)
	}
	if len(a.Gaps) != 1 {
		t.Errorf("gaps: %v", a.Gaps)
	}
	if a.RiskAssessment == nil || a.RiskAssessment.Score != 87 {
		t.Errorf("risk_assessment: %+v", a.RiskAssessment)
	}
}

func TestValidateStatementMissingClassification(t *testing.T) {
	in := strings.Replace(v2AnalysisJSON(),
		`{"text": "The destination is associated with suspicious infrastructure", "classification": "INFERRED", "evidence_refs": ["203.0.113.50"]}`,
		`{"text": "The destination is associated with suspicious infrastructure", "evidence_refs": ["203.0.113.50"]}`, 1)
	_, err := ValidateAnalysisWithContext([]byte(in), v2Context())
	if err == nil {
		t.Fatal("statement without classification accepted")
	}
}

func TestValidateStatementBadClassification(t *testing.T) {
	in := strings.Replace(v2AnalysisJSON(), `"classification": "HYPOTHESIS"`, `"classification": "CERTAIN"`, 1)
	_, err := ValidateAnalysisWithContext([]byte(in), v2Context())
	if err == nil {
		t.Fatal("invalid classification accepted")
	}
}

func TestValidateUnsupportedObservedClaim(t *testing.T) {
	// OBSERVED citing an event that is not in the context must be rejected.
	in := strings.Replace(v2AnalysisJSON(), `"evidence_refs": ["e-98421"]},`, `"evidence_refs": ["e-nope"]},`, 1)
	_, err := ValidateAnalysisWithContext([]byte(in), v2Context())
	if err == nil {
		t.Fatal("OBSERVED citing a nonexistent event accepted")
	}
	if !strings.Contains(err.Error(), "unsupported_observed_claim") {
		t.Errorf("expected unsupported_observed_claim, got: %v", err)
	}
}

func TestValidateInferredNeedsKnownRef(t *testing.T) {
	// INFERRED citing a ref absent from the context must be rejected.
	in := strings.Replace(v2AnalysisJSON(),
		`"classification": "INFERRED", "evidence_refs": ["203.0.113.50"]`,
		`"classification": "INFERRED", "evidence_refs": ["999.999.999.999"]`, 1)
	_, err := ValidateAnalysisWithContext([]byte(in), v2Context())
	if err == nil {
		t.Fatal("INFERRED with unknown ref accepted")
	}
}

func TestValidateSectionNameRef(t *testing.T) {
	// A section key that contains data is a valid ref for INFERRED claims;
	// the same name with no data behind it is not.
	in := strings.Replace(v2AnalysisJSON(),
		`"classification": "INFERRED", "evidence_refs": ["203.0.113.50"]`,
		`"classification": "INFERRED", "evidence_refs": ["related_findings"]`, 1)
	if _, err := ValidateAnalysisWithContext([]byte(in), v2Context()); err == nil {
		t.Fatal("section ref accepted with empty related_findings")
	}
	ctx := v2Context()
	ctx.Related = []FindingInfo{{ID: "f-2", Title: "Beaconing", Severity: "high", Status: "new"}}
	if _, err := ValidateAnalysisWithContext([]byte(in), ctx); err != nil {
		t.Fatalf("section ref rejected despite data: %v", err)
	}
	// Section names never satisfy the OBSERVED event-id rule.
	in = strings.Replace(v2AnalysisJSON(),
		`"classification": "OBSERVED", "evidence_refs": ["e-98421"]},`,
		`"classification": "OBSERVED", "evidence_refs": ["events"]},`, 1)
	if _, err := ValidateAnalysisWithContext([]byte(in), ctx); err == nil {
		t.Fatal("section ref satisfied the OBSERVED rule")
	}
}

func TestValidateLegacyOutputStillAccepted(t *testing.T) {
	// v1 output (no statements) remains valid — the additions are additive.
	if _, err := ValidateAnalysisWithContext([]byte(validAnalysisJSON()), v2Context()); err != nil {
		t.Fatalf("legacy output rejected: %v", err)
	}
}

func TestValidateRiskAssessmentClamped(t *testing.T) {
	in := strings.Replace(v2AnalysisJSON(), `"score": 87`, `"score": 140`, 1)
	a, err := ValidateAnalysisWithContext([]byte(in), v2Context())
	if err != nil {
		t.Fatalf("rejected: %v", err)
	}
	if a.RiskAssessment.Score != 100 {
		t.Errorf("score not clamped: %d", a.RiskAssessment.Score)
	}
}
