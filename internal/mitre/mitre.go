// Package mitre provides a static, provider-neutral MITRE ATT&CK metadata
// catalog. It is embedded data, not a live feed: external threat-intelligence
// integrations can extend or replace it without touching the rest of the
// platform.
package mitre

import (
	"sort"
	"strings"
)

// Tactic is a top-level ATT&CK tactic.
type Tactic struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Order int    `json:"order"`
}

// Technique is an ATT&CK technique (or sub-technique).
type Technique struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	TacticIDs []string `json:"tactic_ids"`
	SubOf     string   `json:"sub_of,omitempty"`
}

var tactics = []Tactic{
	{ID: "TA0043", Name: "Reconnaissance", Order: 1},
	{ID: "TA0042", Name: "Resource Development", Order: 2},
	{ID: "TA0001", Name: "Initial Access", Order: 3},
	{ID: "TA0002", Name: "Execution", Order: 4},
	{ID: "TA0003", Name: "Persistence", Order: 5},
	{ID: "TA0004", Name: "Privilege Escalation", Order: 6},
	{ID: "TA0005", Name: "Defense Evasion", Order: 7},
	{ID: "TA0006", Name: "Credential Access", Order: 8},
	{ID: "TA0007", Name: "Discovery", Order: 9},
	{ID: "TA0008", Name: "Lateral Movement", Order: 10},
	{ID: "TA0009", Name: "Collection", Order: 11},
	{ID: "TA0011", Name: "Command and Control", Order: 12},
	{ID: "TA0010", Name: "Exfiltration", Order: 13},
	{ID: "TA0040", Name: "Impact", Order: 14},
}

var techniques = map[string]Technique{
	"T1110":    {ID: "T1110", Name: "Brute Force", TacticIDs: []string{"TA0006"}},
	"T1110.001": {ID: "T1110.001", Name: "Password Guessing", TacticIDs: []string{"TA0006"}, SubOf: "T1110"},
	"T1110.003": {ID: "T1110.003", Name: "Credential Stuffing", TacticIDs: []string{"TA0006"}, SubOf: "T1110"},
	"T1078":    {ID: "T1078", Name: "Valid Accounts", TacticIDs: []string{"TA0001", "TA0003", "TA0004", "TA0008"}},
	"T1566":    {ID: "T1566", Name: "Phishing", TacticIDs: []string{"TA0001"}},
	"T1566.001": {ID: "T1566.001", Name: "Spearphishing Attachment", TacticIDs: []string{"TA0001"}, SubOf: "T1566"},
	"T1566.004": {ID: "T1566.004", Name: "Spearphishing Link", TacticIDs: []string{"TA0001"}, SubOf: "T1566"},
	"T1059":    {ID: "T1059", Name: "Command and Scripting Interpreter", TacticIDs: []string{"TA0002", "TA0004", "TA0005"}},
	"T1059.001": {ID: "T1059.001", Name: "PowerShell", TacticIDs: []string{"TA0002", "TA0004", "TA0005"}, SubOf: "T1059"},
	"T1059.003": {ID: "T1059.003", Name: "Windows Command Shell", TacticIDs: []string{"TA0002", "TA0004", "TA0005"}, SubOf: "T1059"},
	"T1059.004": {ID: "T1059.004", Name: "Unix Shell", TacticIDs: []string{"TA0002", "TA0004", "TA0005"}, SubOf: "T1059"},
	"T1078.002": {ID: "T1078.002", Name: "Domain Account", TacticIDs: []string{"TA0001", "TA0003", "TA0004", "TA0008"}, SubOf: "T1078"},
	"T1078.004": {ID: "T1078.004", Name: "Cloud Accounts", TacticIDs: []string{"TA0001", "TA0003", "TA0004", "TA0008"}, SubOf: "T1078"},
	"T1543":    {ID: "T1543", Name: "Create or Modify System Process", TacticIDs: []string{"TA0003", "TA0004"}},
	"T1543.002": {ID: "T1543.002", Name: "Service", TacticIDs: []string{"TA0003", "TA0004"}, SubOf: "T1543"},
	"T1053.005": {ID: "T1053.005", Name: "Scheduled Task", TacticIDs: []string{"TA0003", "TA0004"}, SubOf: "T1053"},
	"T1548":    {ID: "T1548", Name: "Abuse Elevation of Privilege", TacticIDs: []string{"TA0004"}},
	"T1548.002": {ID: "T1548.002", Name: "Bypass User Account Control", TacticIDs: []string{"TA0004"}, SubOf: "T1548"},
	"T1068":    {ID: "T1068", Name: "Exploitation for Privilege Escalation", TacticIDs: []string{"TA0004"}},
	"T1068.003": {ID: "T1068.003", Name: "Local Elevated Execution", TacticIDs: []string{"TA0004"}, SubOf: "T1068"},
	"T1070":    {ID: "T1070", Name: "Indicator Removal", TacticIDs: []string{"TA0005"}},
	"T1070.001": {ID: "T1070.001", Name: "Clear Windows Event Log", TacticIDs: []string{"TA0005"}, SubOf: "T1070"},
	"T1070.004": {ID: "T1070.004", Name: "File Deletion", TacticIDs: []string{"TA0005"}, SubOf: "T1070"},
	"T1497":    {ID: "T1497", Name: "Virtualization/Sandbox Evasion", TacticIDs: []string{"TA0005"}},
	"T1497.001": {ID: "T1497.001", Name: "System Modification", TacticIDs: []string{"TA0005"}, SubOf: "T1497"},
	"T1140":    {ID: "T1140", Name: "Deobfuscate/Decode Files or Information", TacticIDs: []string{"TA0005"}},
	"T1027":    {ID: "T1027", Name: "Obfuscated Files or Information", TacticIDs: []string{"TA0005"}},
	"T1562":    {ID: "T1562", Name: "Impair Defenses", TacticIDs: []string{"TA0005", "TA0011"}},
	"T1562.001": {ID: "T1562.001", Name: "Disable or Modify Tools", TacticIDs: []string{"TA0005", "TA0011"}, SubOf: "T1562"},
	"T1562.002": {ID: "T1562.002", Name: "Disable or Modify System Firewall", TacticIDs: []string{"TA0005", "TA0011"}, SubOf: "T1562"},
	"T1562.006": {ID: "T1562.006", Name: "Indicator Blocking", TacticIDs: []string{"TA0005"}, SubOf: "T1562"},
	"T1003":    {ID: "T1003", Name: "OS Credential Dumping", TacticIDs: []string{"TA0006"}},
	"T1003.001": {ID: "T1003.001", Name: "LSASS Memory", TacticIDs: []string{"TA0006"}, SubOf: "T1003"},
	"T1056":    {ID: "T1056", Name: "Input Capture", TacticIDs: []string{"TA0006"}},
	"T1056.001": {ID: "T1056.001", Name: "Keylogging", TacticIDs: []string{"TA0006"}, SubOf: "T1056"},
	"T1112":    {ID: "T1112", Name: "Modify Registry", TacticIDs: []string{"TA0006"}},
	"T1552":    {ID: "T1552", Name: "Unsecured Credentials", TacticIDs: []string{"TA0006"}},
	"T1555":    {ID: "T1555", Name: "Credentials from Password Stores", TacticIDs: []string{"TA0006"}},
	"T1555.003": {ID: "T1555.003", Name: "Credentials from Web Browsers", TacticIDs: []string{"TA0006"}, SubOf: "T1555"},
	"T1016":    {ID: "T1016", Name: "System Network Configuration Discovery", TacticIDs: []string{"TA0007"}},
	"T1018":    {ID: "T1018", Name: "Remote System Discovery", TacticIDs: []string{"TA0007", "TA0009"}},
	"T1046":    {ID: "T1046", Name: "Network Service Scanning", TacticIDs: []string{"TA0007"}},
	"T1057":    {ID: "T1057", Name: "Process Discovery", TacticIDs: []string{"TA0007"}},
	"T1082":    {ID: "T1082", Name: "System Discovery", TacticIDs: []string{"TA0007"}},
	"T1087":    {ID: "T1087", Name: "Account Discovery", TacticIDs: []string{"TA0007"}},
	"T1087.002": {ID: "T1087.002", Name: "Domain Account", TacticIDs: []string{"TA0007"}, SubOf: "T1087"},
	"T1205":    {ID: "T1205", Name: "Traffic Signaling", TacticIDs: []string{"TA0007", "TA0011"}},
	"T1482":    {ID: "T1482", Name: "Domain Trust Discovery", TacticIDs: []string{"TA0007"}},
	"T1021":    {ID: "T1021", Name: "Remote Services", TacticIDs: []string{"TA0008"}},
	"T1021.002": {ID: "T1021.002", Name: "SMB/Windows Admin Shares", TacticIDs: []string{"TA0008"}, SubOf: "T1021"},
	"T1021.006": {ID: "T1021.006", Name: "Windows Remote Management", TacticIDs: []string{"TA0008"}, SubOf: "T1021"},
	"T1570":    {ID: "T1570", Name: "Lateral Tool Transfer", TacticIDs: []string{"TA0008"}},
	"T1039":    {ID: "T1039", Name: "Data from Information Repositories", TacticIDs: []string{"TA0009"}},
	"T1074":    {ID: "T1074", Name: "Data Staged", TacticIDs: []string{"TA0009"}},
	"T1119":    {ID: "T1119", Name: "Automated Collection", TacticIDs: []string{"TA0009"}},
	"T1560":    {ID: "T1560", Name: "Archive Collected Data", TacticIDs: []string{"TA0009"}},
	"T1567":    {ID: "T1567", Name: "Data from Network Shared Drive", TacticIDs: []string{"TA0009"}},
	"T1041":    {ID: "T1041", Name: "Exfiltration Over C2 Channel", TacticIDs: []string{"TA0010"}},
	"T1048":    {ID: "T1048", Name: "Exfiltration Over Alternative Protocol", TacticIDs: []string{"TA0010"}},
	"T1048.002": {ID: "T1048.002", Name: "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol", TacticIDs: []string{"TA0010"}, SubOf: "T1048"},
	"T1052":    {ID: "T1052", Name: "Exfiltration Over Physical Medium", TacticIDs: []string{"TA0010"}},
	"T1537":    {ID: "T1537", Name: "Transfer Data to Cloud Storage", TacticIDs: []string{"TA0010"}},
	"T1071":    {ID: "T1071", Name: "Application Layer Protocol", TacticIDs: []string{"TA0011"}},
	"T1071.001": {ID: "T1071.001", Name: "Web Protocols", TacticIDs: []string{"TA0011"}, SubOf: "T1071"},
	"T1571":    {ID: "T1571", Name: "Non-Standard Port", TacticIDs: []string{"TA0011"}},
	"T1573":    {ID: "T1573", Name: "Encrypted Channel", TacticIDs: []string{"TA0011"}},
	"T1132":    {ID: "T1132", Name: "Data Encoding", TacticIDs: []string{"TA0011"}},
	"T1132.001": {ID: "T1132.001", Name: "Standard Encoding", TacticIDs: []string{"TA0011"}, SubOf: "T1132"},
	"T1020":    {ID: "T1020", Name: "Automated Exfiltration", TacticIDs: []string{"TA0010"}},
	"T1485":    {ID: "T1485", Name: "Data Destruction", TacticIDs: []string{"TA0040"}},
	"T1486":    {ID: "T1486", Name: "Data Encrypted for Impact", TacticIDs: []string{"TA0040"}},
	"T1490":    {ID: "T1490", Name: "Inhibit System Function", TacticIDs: []string{"TA0040"}},
	"T1491":    {ID: "T1491", Name: "Defacement", TacticIDs: []string{"TA0040"}},
}

// Tactics returns the full tactic list in display order.
func Tactics() []Tactic {
	out := make([]Tactic, len(tactics))
	copy(out, tactics)
	return out
}

// Techniques returns the full technique catalog sorted by ID.
func Techniques() []Technique {
	out := make([]Technique, 0, len(techniques))
	for _, t := range techniques {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID[:5] != out[j].ID[:5] {
			return out[i].ID[:5] < out[j].ID[:5]
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Lookup resolves a technique ID (case-insensitive). ok=false when unknown.
func Lookup(id string) (Technique, bool) {
	t, ok := techniques[normID(id)]
	return t, ok
}

// TacticName resolves a tactic ID to its display name. ok=false when unknown.
func TacticName(id string) (string, bool) {
	for _, t := range tactics {
		if strings.EqualFold(t.ID, id) {
			return t.Name, true
		}
	}
	return "", false
}

// ParentOf returns the parent technique for a sub-technique, or "".
func ParentOf(id string) string {
	if t, ok := techniques[normID(id)]; ok {
		return t.SubOf
	}
	return ""
}

// normID canonicalizes a technique ID for lookups: trims, uppercases and
// restores a single leading "T", so both "t1059.001" and "1059.001" resolve.
func normID(id string) string {
	id = strings.TrimSpace(strings.ToUpper(id))
	id = strings.TrimPrefix(id, "T")
	return "T" + id
}
