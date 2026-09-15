package parsers

import (
	"regexp"
	"strconv"
	"strings"

	"quetzalog/pkg/event"
)

// CEF (Common Event Format, ArcSight) records:
//
//	CEF:8|Vendor|Product|Version|SignatureID|Name|Severity|key=value ...
//
// Extension values may contain escaped pipes (\|).

// cefKeyBoundary locates "key=" boundaries in the CEF extension. Keys are
// word characters at a value boundary (start or after whitespace); a
// value may contain spaces and escaped pipes. Known limitation: a value
// containing an unescaped " word=" sequence is truncated at that point.
var cefKeyBoundary = regexp.MustCompile(`(?i)(?:^|\s)([A-Za-z0-9_.]+)=`)

type cefParser struct{}

func (cefParser) Name() string    { return "cef" }
func (cefParser) Version() string { return "1" }

func (cefParser) Parse(raw []byte) (*Parsed, bool) {
	line := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(line, "CEF:") {
		return nil, false
	}
	// Split on unescaped pipes: the first 7 segments are the header.
	fields := splitUnescapedPipes(line[len("CEF:"):])
	if len(fields) < 8 {
		return nil, false
	}
	out := &Parsed{}

	out.Attrs()["cef.version"] = fields[0]
	out.Attrs()["cef.vendor"] = fields[1]
	out.Attrs()["cef.product"] = fields[2]
	out.Attrs()["cef.signature_id"] = fields[4]
	if name := unescapeCEF(fields[5]); name != "" {
		out.Message = name
	}

	// Severity: numeric 0-10, or a name.
	if n, err := strconv.Atoi(fields[6]); err == nil && n >= 0 && n <= 10 {
		out.Severity = cefSeverity(n)
	} else if s := event.ParseSeverity(fields[6]); s != "" {
		out.Severity = s
	}

	// Extension key=value pairs.
	for k, v := range parseCEFExtension(fields[7]) {
		switch k {
		case "rt":
			if t := event.ParseTimestamp(v); !t.IsZero() {
				out.Timestamp = t
			}
		case "src":
			out.SourceIP = v
		case "dst":
			out.DestIP = v
		case "spt":
			out.SourcePort = atoiDefault(v, 0)
		case "dpt":
			out.DestPort = atoiDefault(v, 0)
		case "suser":
			out.User = v
		case "dvchost":
			out.Host = v
		case "dhost":
			if out.Host == "" {
				out.Host = v
			}
		default:
			out.Attrs()[k] = v
		}
	}

	return out, true
}

// cefSeverity maps CEF numeric severity (0-10) onto Quetzalog's scale.
func cefSeverity(n int) string {
	switch {
	case n >= 8:
		return "critical"
	case n >= 6:
		return "err"
	case n >= 4:
		return "warning"
	case n >= 1:
		return "notice"
	default:
		return "debug"
	}
}

// splitUnescapedPipes splits on '|' not preceded by a backslash.
func splitUnescapedPipes(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++ // skip escaped char
			continue
		}
		if s[i] == '|' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func parseCEFExtension(ext string) map[string]string {
	out := map[string]string{}
	matches := cefKeyBoundary.FindAllStringSubmatchIndex(ext, -1)
	for i, m := range matches {
		key := ext[m[2]:m[3]]
		valStart := m[1]
		valEnd := len(ext)
		if i+1 < len(matches) {
			valEnd = matches[i+1][0]
		}
		v := strings.Trim(ext[valStart:valEnd], " ")
		out[key] = unescapeCEF(v)
	}
	return out
}

func unescapeCEF(v string) string {
	v = strings.ReplaceAll(v, `\|`, "|")
	v = strings.ReplaceAll(v, `\\`, `\`)
	return v
}

func atoiDefault(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}
