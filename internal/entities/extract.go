package entities

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Extracted is one entity candidate extracted from a raw observation.
// Aliases carries the original (pre-normalization) forms.
type Extracted struct {
	Type    string
	Value   string
	Aliases []string
}

// Extraction types produced from events/attributes.
const (
	TypeUser     = "user"
	TypeHost     = "host"
	TypeIP       = "ip"
	TypeDomain   = "domain"
	TypeURL      = "url"
	TypeEmail    = "email"
	TypeHash     = "hash"
	TypeProcess  = "process"
	TypeFile     = "file"
)

var reDomain = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z]{2,})?$`)

var reHash = regexp.MustCompile(`^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$`)

// NormalizeUser strips domain prefixes ("DOMAIN\\mauro", "domain/mauro") and
// lowercases; the original form is kept as an alias.
func NormalizeUser(s string) (string, []string) {
	s = strings.TrimSpace(s)
	aliases := []string{}
	if i := strings.IndexAny(s, `\/`); i >= 0 {
		aliases = append(aliases, s)
		s = s[i+1:]
	}
	// NT backslash form "DOMAIN\\user".
	if i := strings.LastIndex(s, `\`); i >= 0 {
		aliases = append(aliases, s)
		s = s[i+1:]
	}
	canonical := strings.ToLower(s)
	return canonical, aliases
}

// NormalizeHost uppercases host names (FQDN canonical form); IPs are
// returned unchanged and are not turned into hosts.
func NormalizeHost(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}

// NormalizeDomain lowercases, strips ports and trailing dots.
func NormalizeDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	if i := strings.IndexByte(s, ':'); i > 0 {
		s = s[:i]
	}
	return s
}

// NormalizeURL keeps scheme+host lowercased, path case preserved.
func NormalizeURL(s string) string {
	s = strings.TrimSpace(s)
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return s
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	if u.Path == "" && u.RawQuery == "" && u.Fragment == "" {
		return scheme + "://" + host
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, u.RequestURI())
}

// NormalizeProcess returns the basename (lowercase on POSIX, .exe kept on
// Windows) plus the full path as an alias.
func NormalizeProcess(s string) (string, []string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	i := strings.LastIndexAny(s, `/\`)
	if i < 0 {
		return strings.ToLower(s), nil
	}
	base := s[i+1:]
	if strings.HasSuffix(strings.ToLower(base), ".exe") {
		return base, []string{s}
	}
	return strings.ToLower(base), []string{s}
}

// NormalizeHash lowercases hashes; returns "" when the value is not a
// plausible MD5/SHA-1/SHA-256 digest.
func NormalizeHash(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if !reHash.MatchString(s) {
		return ""
	}
	return s
}

// NormalizeEmail lowercases the local-part-and-domain form.
func NormalizeEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// ExtractFromAttributes pulls v2 entity candidates out of an event's
// attributes (domain, url, email, hashes, file, process, user forms).
func ExtractFromAttributes(attrs map[string]any) []Extracted {
	if len(attrs) == 0 {
		return nil
	}
	out := []Extracted{}
	add := func(typ, value string, aliases ...string) {
		if value == "" {
			return
		}
		out = append(out, Extracted{Type: typ, Value: value, Aliases: aliases})
	}

	if v, ok := attrs["domain"].(string); ok {
		add(TypeDomain, NormalizeDomain(v))
	}
	if v, ok := attrs["url"].(string); ok {
		add(TypeURL, NormalizeURL(v))
	}
	if v, ok := attrs["email"].(string); ok {
		add(TypeEmail, NormalizeEmail(v))
	}
	if v, ok := attrs["file_hash"].(string); ok {
		if h := NormalizeHash(v); h != "" {
			add(TypeHash, h)
		}
	}
	if v, ok := attrs["file"].(string); ok {
		add(TypeFile, strings.TrimSpace(v))
	}
	if v, ok := attrs["process"].(string); ok {
		if p, al := NormalizeProcess(v); p != "" {
			add(TypeProcess, p, al...)
		}
	}
	if v, ok := attrs["user"].(string); ok {
		if u, al := NormalizeUser(v); u != "" {
			add(TypeUser, u, al...)
		}
	}
	return out
}
