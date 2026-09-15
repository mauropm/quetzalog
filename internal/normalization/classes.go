// Package normalization defines the canonical source-class taxonomy that
// higher layers (telemetry coverage, detection data-source requirements,
// threat models) reason about. A source class groups the log streams of
// one telemetry concern, regardless of transport or product flavor.
//
// The taxonomy is data, not code: adding a new platform (e.g. a mainframe
// collector) means adding a class constant here, not touching consumers.
package normalization

// Canonical source classes (Phase 2 taxonomy).
const (
	// Operating systems
	ClassWinSecurity   = "os.windows.security"
	ClassWinSysmon     = "os.windows.sysmon"
	ClassWinPowerShell = "os.windows.powershell"
	ClassWinDefender   = "os.windows.defender"
	ClassWinDNS        = "os.windows.dns"
	ClassWinRDP        = "os.windows.rdp"
	ClassWinKerberos   = "os.windows.kerberos"
	ClassMacUnified    = "os.macos.unified"
	ClassMacLaunchd    = "os.macos.launchd"
	ClassMacEndpoint   = "os.macos.endpoint"
	ClassLinuxAuditd   = "os.linux.auditd"
	ClassLinuxAuth     = "os.linux.auth"
	ClassLinuxSSHD     = "os.linux.sshd"
	ClassLinuxSudo     = "os.linux.sudo"
	ClassLinuxJournal  = "os.linux.journal"
	ClassLinuxSyslog   = "os.linux.syslog"
	ClassSolarisAudit  = "os.solaris.audit"
	ClassOSGeneric     = "os.generic"

	// Applications
	ClassWebAccess  = "web.access"
	ClassWebError   = "web.error"
	ClassDB         = "db.log"
	ClassIdentity   = "identity.log"
	ClassAppGeneric = "application.generic"

	// Network
	ClassNetFirewall = "net.firewall"
	ClassNetIDS      = "net.ids"
	ClassNetDNS      = "net.dns"
	ClassNetDHCP     = "net.dhcp"
	ClassNetFlow     = "net.flow"
	ClassNetVPN      = "net.vpn"
	ClassNetProxy    = "net.proxy"

	// Cloud / containers
	ClassCloudAudit   = "cloud.audit"
	ClassCloudFlow    = "cloud.flow"
	ClassCloudIAM     = "cloud.iam"
	ClassContainer    = "container.runtime"
	ClassK8sAudit     = "k8s.audit"
	ClassMainframeSMF = "mainframe.smf"
	ClassMainframeRAC = "mainframe.racf"

	// Catch-all
	ClassGeneric = "generic"
)

// AllClasses lists every canonical source class.
var AllClasses = []string{
	ClassWinSecurity, ClassWinSysmon, ClassWinPowerShell, ClassWinDefender,
	ClassWinDNS, ClassWinRDP, ClassWinKerberos,
	ClassMacUnified, ClassMacLaunchd, ClassMacEndpoint,
	ClassLinuxAuditd, ClassLinuxAuth, ClassLinuxSSHD, ClassLinuxSudo,
	ClassLinuxJournal, ClassLinuxSyslog, ClassSolarisAudit, ClassOSGeneric,
	ClassWebAccess, ClassWebError, ClassDB, ClassIdentity, ClassAppGeneric,
	ClassNetFirewall, ClassNetIDS, ClassNetDNS, ClassNetDHCP, ClassNetFlow,
	ClassNetVPN, ClassNetProxy,
	ClassCloudAudit, ClassCloudFlow, ClassCloudIAM, ClassContainer,
	ClassK8sAudit, ClassMainframeSMF, ClassMainframeRAC,
	ClassGeneric,
}

// knownClasses is the lookup set for AllClasses.
var knownClasses = func() map[string]bool {
	m := make(map[string]bool, len(AllClasses))
	for _, c := range AllClasses {
		m[c] = true
	}
	return m
}()

// ClassFor maps a source_type value to a source class.
//
// Exact taxonomy values map to themselves. Legacy/transport source types
// (syslog, file:*, hec_raw, json, otlp, ...) have no inherent telemetry
// concern and map to the generic class until a normalizer assigns a
// specific class. This keeps coverage analysis honest: unknown telemetry
// is "generic", not silently filed under the wrong concern.
func ClassFor(sourceType string) string {
	if knownClasses[sourceType] {
		return sourceType
	}
	return ClassGeneric
}

// IsKnownClass reports whether c is a canonical source class.
func IsKnownClass(c string) bool {
	return knownClasses[c]
}
