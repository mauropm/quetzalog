package ai

import (
	"log/slog"
	"regexp"
	"strings"
)

// Redaction is the deterministic secret/PII pass applied to every untrusted
// text that enters the analyst context (event messages, usernames, threat
// intel descriptions, payloads) before any prompt layer is assembled
// (ai-security-analysis.md §1, spec §44/§74.11). It is deterministic: the
// same input always yields the same output, and it is logged — which
// categories were redacted, never the values.
var redactPatterns = []struct {
	label string
	re    *regexp.Regexp
}{
	// Assignment-style secrets: password=..., token "x", api_key: ...
	{label: "password", re: regexp.MustCompile("(?i)\\b(password|passwd|pwd|passphrase)\\b(\\s*[=:]\\s*)?[^\\s\"',;)]{4,}")},
	{label: "token", re: regexp.MustCompile("(?i)\\b(api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|client[_-]?secret)\\b(\\s*[=:]\\s*)?[^\\s\"',;)]{8,}")},
	// Bearer/basic credential material.
	{label: "token", re: regexp.MustCompile("(?i)\\b(bearer|basic)\\s+[a-z0-9+/._=-]{16,}")},
	// AWS-style access key ids.
	{label: "token", re: regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b`)},
	// Session cookies: value after set-cookie/cookie: up to the next
	// semicolon or newline.
	{label: "cookie", re: regexp.MustCompile(`(?i)\b(set-cookie|cookie)\s*:\s*[^\n;,]{4,}`)},
	// US-style SSN.
	{label: "ssn", re: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
}

// RedactText replaces secret/PII patterns in s with deterministic markers.
// It returns the redacted string and the categories that fired (empty when
// nothing was redacted). The redacted values are never returned.
func RedactText(s string) (string, []string) {
	if s == "" {
		return s, nil
	}
	var fired []string
	out := s
	for _, p := range redactPatterns {
		if p.re.MatchString(out) {
			if !contains(fired, p.label) {
				fired = append(fired, p.label)
			}
			out = p.re.ReplaceAllString(out, "[REDACTED:"+p.label+"]")
		}
	}
	return out, fired
}

// logRedaction records which categories were redacted in one text. Values
// are intentionally excluded from the log record.
func logRedaction(logger *slog.Logger, where string, categories []string) {
	if logger == nil || len(categories) == 0 {
		return
	}
	logger.Info("ai context redaction", "where", where, "categories", strings.Join(categories, ","))
}
