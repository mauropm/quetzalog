// Package threatintel implements the threat-intelligence layer: the
// indicator model (IOCs with multi-source confidence), provider abstraction
// (internal + external feeds), and the correlation of indicator hits
// against the event stream.
//
// Design invariants (docs/threat-intelligence-architecture.md, principles
// 6 and 10): external TI is untrusted input — provider payloads are
// validated and quarantined in the indicator tables; a single weak source
// cannot classify an indicator malicious (confidence is corroborated
// across sources); attribution follows the evidence ladder.
package threatintel

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// IndicatorTypes are the supported indicator kinds.
var IndicatorTypes = []string{
	"ip", "domain", "url", "hash", "file", "email",
	"user", "registry", "mutex", "port", "asn",
}

// Severities shared with the rest of the system.
var Severities = []string{"low", "medium", "high", "critical"}

// Attribution ladder (weakest → strongest), principle 7.
var AttributionLadder = []string{"associated", "consistent", "possibly_related", "attributed"}

// Indicator is one observed intelligence item.
type Indicator struct {
	ID              string    `json:"id"`
	Type            string    `json:"type"`
	Value           string    `json:"value"`
	NormalizedValue string    `json:"normalized_value"`
	Severity        string    `json:"severity"`
	Description     string    `json:"description,omitempty"`
	Source          string    `json:"source"`
	Confidence      float64   `json:"confidence"`
	FirstSeen       time.Time `json:"first_seen,omitempty"`
	LastSeen        time.Time `json:"last_seen,omitempty"`
	HitCount        int       `json:"hit_count"`
}

// InIndicator is what a provider or analyst submits.
type InIndicator struct {
	Type        string `json:"type"`
	Value       string `json:"value"`
	Severity    string `json:"severity,omitempty"`
	Description string `json:"description,omitempty"`
	Source      string `json:"source,omitempty"`
	Confidence  float64 `json:"confidence,omitempty"`
	Reliability float64 `json:"reliability,omitempty"`
	SourceURL   string `json:"source_url,omitempty"`
	Actor       string `json:"actor,omitempty"`
}

// SourceRow is one provenance record for an indicator.
type SourceRow struct {
	IndicatorID string  `json:"indicator_id"`
	Source      string  `json:"source"`
	SourceURL   string  `json:"source_url,omitempty"`
	Reliability float64 `json:"reliability"`
	Confidence  float64 `json:"confidence"`
	FirstSeen   time.Time `json:"first_seen,omitempty"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
}

// Actor is a threat actor (group/individual/state-sponsored).
type Actor struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Aka         string `json:"aka,omitempty"`
	Type        string `json:"type,omitempty"`
	Country     string `json:"country,omitempty"`
	Motivation  string  `json:"motivation,omitempty"`
	Description string `json:"description,omitempty"`
	FirstSeen   time.Time `json:"first_seen,omitempty"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
	Indicators  []Indicator `json:"indicators,omitempty"`
}

// Campaign is an organized effort, optionally attributed to an actor.
type Campaign struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ActorID     string `json:"actor_id,omitempty"`
	Description string `json:"description,omitempty"`
	FirstSeen   time.Time `json:"first_seen,omitempty"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
}

// MalwareFamily is a named malware family.
type MalwareFamily struct {
	ID          string `json:"id"`
	Family      string `json:"family"`
	Description string `json:"description,omitempty"`
	FirstSeen   time.Time `json:"first_seen,omitempty"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
}

// ProviderState is the sync status of one TI provider.
type ProviderState struct {
	Provider       string `json:"provider"`
	LastSync       time.Time `json:"last_sync,omitempty"`
	LastStatus     string `json:"last_status,omitempty"`
	LastError      string `json:"last_error,omitempty"`
	IndicatorCount int    `json:"indicator_count"`
}

// Normalize reduces an indicator value to its canonical form for
// matching: IPs in dotted-quad, domains/URLs/emails lowercased, hashes
// lowercased without algorithm prefix. Unparseable values are lowercased
// verbatim — normalization must never fail, it only canonicalizes.
func Normalize(typ, value string) string {
	v := strings.TrimSpace(value)
	switch typ {
	case "ip":
		if ip := net.ParseIP(v); ip != nil {
			return ip.String()
		}
	case "domain", "email":
		v = strings.TrimPrefix(v, ".")
		v = strings.TrimSuffix(v, ".")
	case "url":
		// Only the host is case-insensitive; the path may be, so preserve
		// its case. Return early to skip the global lowercase below.
		if i := strings.Index(v, "://"); i >= 0 {
			host := v[i+3:]
			if j := strings.IndexAny(host, "/?#"); j >= 0 {
				return v[:i+3] + strings.ToLower(host[:j]) + host[j:]
			}
			return v[:i+3] + strings.ToLower(host)
		}
	case "hash":
		if parts := strings.SplitN(v, ":", 2); len(parts) == 2 {
			alg := strings.ToLower(strings.TrimSpace(parts[0]))
			if md5like(alg) || shaLike(alg) {
				v = parts[1]
			}
		}
	}
	return strings.ToLower(v)
}

func md5like(s string) bool {
	return len(s) == 3 || s == "md5" || s == "md4"
}

func shaLike(s string) bool {
	return s == "sha1" || s == "sha256" || s == "sha512" || s == "ssdeep"
}

// ValidateIndicator checks an InIndicator's invariants.
func ValidateIndicator(in InIndicator) error {
	if !containsStr(IndicatorTypes, in.Type) {
		return fmt.Errorf("invalid indicator type %q", in.Type)
	}
	if strings.TrimSpace(in.Value) == "" {
		return fmt.Errorf("indicator value is required")
	}
	if in.Severity == "" {
		in.Severity = "medium"
	}
	if !containsStr(Severities, in.Severity) {
		return fmt.Errorf("invalid severity %q", in.Severity)
	}
	if in.Confidence < 0 || in.Confidence > 1 {
		return fmt.Errorf("confidence must be within [0,1]")
	}
	if in.Reliability < 0 || in.Reliability > 1 {
		return fmt.Errorf("reliability must be within [0,1]")
	}
	return nil
}

func containsStr(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
