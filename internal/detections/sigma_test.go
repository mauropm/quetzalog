package detections

import (
	"strings"
	"testing"
)

func TestImportSigma_BasicSelection(t *testing.T) {
	yamlDoc := `
title: Suspicious Powershell
status: active
logsource:
  product: windows
  category: security
detection:
  selection:
    EventID: 4688
    Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
condition: selection
level: high
tags:
  - attack.execution
  - attack.command_and_control
  - attack.tactic.execution
  - attack.t1059.001
`
	rule, err := ImportSigma([]byte(yamlDoc))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if rule.Kind != "spl" {
		t.Errorf("kind: %q, want spl", rule.Kind)
	}
	if rule.Severity != "high" {
		t.Errorf("severity: %q, want high", rule.Severity)
	}
	if rule.MITRETactic != "TA0002" {
		t.Errorf("tactic: %q, want TA0002", rule.MITRETactic)
	}
	if rule.MITRETechnique != "T1059.001" {
		t.Errorf("technique: %q, want T1059.001", rule.MITRETechnique)
	}
	if !strings.Contains(rule.Query, "EventID = '4688'") {
		t.Errorf("query missing EventID predicate: %q", rule.Query)
	}
	if !strings.Contains(rule.Query, "source_type=os.windows.security") {
		t.Errorf("query missing source_type filter: %q", rule.Query)
	}
	if len(rule.DataSources) != 1 || rule.DataSources[0] != "os.windows.security" {
		t.Errorf("data_sources: %v", rule.DataSources)
	}
	// Tagged sigma:<name>@<version>.
	sigmaTagged := false
	for _, tag := range rule.Tags {
		if strings.HasPrefix(tag, "sigma:") {
			sigmaTagged = true
		}
	}
	if !sigmaTagged {
		t.Errorf("tags missing sigma:<name>@<version>: %v", rule.Tags)
	}
}

func TestImportSigma_ContainsAndList(t *testing.T) {
	yamlDoc := `
title: Encoded Powershell
status: active
logsource:
  product: windows
  category: powershell
detection:
  selection:
    Commandline|contains: -enc
    ParentImage:
      - C:\Windows\Explorer.exe
      - C:\Windows\System32\svchost.exe
condition: selection
level: medium
`
	rule, err := ImportSigma([]byte(yamlDoc))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if !strings.Contains(rule.Query, "Commandline LIKE '%-enc%'") {
		t.Errorf("query missing contains predicate: %q", rule.Query)
	}
	if !strings.Contains(rule.Query, "ParentImage IN (") {
		t.Errorf("query missing in predicate: %q", rule.Query)
	}
}

func TestImportSigma_AndNot(t *testing.T) {
	yamlDoc := `
title: RDP Logon
status: active
logsource:
  product: windows
  category: security
detection:
  selection:
    EventID: 4624
  filter:
    LogonType: 3
condition: selection and not filter
level: low
`
	rule, err := ImportSigma([]byte(yamlDoc))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if !strings.Contains(rule.Query, "EventID = '4624'") {
		t.Errorf("query missing selection predicate: %q", rule.Query)
	}
	if !strings.Contains(rule.Query, "NOT (LogonType = '3')") {
		t.Errorf("query missing negated filter: %q", rule.Query)
	}
}

func TestImportSigma_OfThemThreshold(t *testing.T) {
	yamlDoc := `
title: Failed Logins
status: active
logsource:
  product: linux
  category: auth
detection:
  selection:
    action: login_failed
condition: 5 of them
level: high
`
	rule, err := ImportSigma([]byte(yamlDoc))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if rule.Threshold == nil || rule.Threshold.Count != 5 {
		t.Errorf("threshold: %+v, want count 5", rule.Threshold)
	}
	if !strings.Contains(rule.Query, "action = 'login_failed'") {
		t.Errorf("query missing predicate: %q", rule.Query)
	}
}

func TestImportSigma_Unsupported(t *testing.T) {
	yamlDoc := `
title: Bad Rule
status: active
logsource:
  product: windows
  category: security
detection:
  selection:
    Image|re: ^C:\\Windows\\
    Commandline|contains: -enc
condition: selection
level: high
`
	_, err := ImportSigma([]byte(yamlDoc))
	if err == nil {
		t.Fatalf("expected error for unsupported re clause")
	}
	se, ok := err.(*SigmaError)
	if !ok {
		t.Fatalf("expected *SigmaError, got %T: %v", err, err)
	}
	if len(se.Unsupported) != 1 || !strings.Contains(se.Unsupported[0], "re") {
		t.Errorf("unsupported clauses: %v", se.Unsupported)
	}
}

func TestImportSigma_NonActiveStatus(t *testing.T) {
	yamlDoc := `
title: Test Rule
status: test
logsource:
  product: windows
detection:
  selection:
    EventID: 1
condition: selection
`
	_, err := ImportSigma([]byte(yamlDoc))
	if err == nil {
		t.Fatalf("expected error for non-active status")
	}
	if strings.Contains(err.Error(), "SigmaError") {
		t.Errorf("non-active status should be a plain error, got: %v", err)
	}
}
