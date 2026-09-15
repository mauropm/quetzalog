package parsers

import (
	"strconv"
	"strings"

	"quetzalog/pkg/event"
)

// LEEF (Log Event and Evidence Format, IBM QRadar) records:
//
//	LEEF:2.0 key=value!key2=value2!...
//
// Inside values, '!' is escaped as \!, '\' as \\, and '=' as \=.

type leefParser struct{}

func (leefParser) Name() string    { return "leef" }
func (leefParser) Version() string { return "1" }

func (leefParser) Parse(raw []byte) (*Parsed, bool) {
	line := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(line, "LEEF:") {
		return nil, false
	}
	rec := line[len("LEEF:"):]
	idx := strings.IndexByte(rec, ' ')
	if idx < 0 {
		return nil, false
	}
	// rec[:idx] is the format version (e.g. "2.0"); the record follows.
	record := rec[idx+1:]
	if record == "" {
		return nil, false
	}

	out := &Parsed{}
	for _, tok := range splitUnescapedBanges(record) {
		if tok == "" {
			continue
		}
		eq := strings.IndexByte(tok, '=')
		if eq <= 0 {
			continue
		}
		k := unescapeLEEF(tok[:eq])
		v := unescapeLEEF(tok[eq+1:])
		switch k {
		case "timestamp":
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				out.Timestamp = event.ParseTimestamp(strconv.FormatFloat(f, 'f', -1, 64))
			}
		case "hostname":
			out.Host = v
		case "username":
			out.User = v
		case "srcip":
			out.SourceIP = v
		case "dstip":
			out.DestIP = v
		case "srcport":
			out.SourcePort = atoiDefault(v, 0)
		case "dstport":
			out.DestPort = atoiDefault(v, 0)
		case "severity":
			out.Severity = event.ParseSeverity(v)
		case "eventtype", "type":
			if out.EventType == "" {
				out.EventType = v
			}
		case "msg", "message":
			if out.Message == "" {
				out.Message = v
			}
		default:
			out.Attrs()[k] = v
		}
	}
	return out, true
}

// splitUnescapedBanges splits a LEEF record on '!' not preceded by a
// backslash.
func splitUnescapedBanges(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == '!' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func unescapeLEEF(v string) string {
	var b strings.Builder
	b.Grow(len(v))
	for i := 0; i < len(v); i++ {
		if v[i] == '\\' && i+1 < len(v) {
			b.WriteByte(v[i+1])
			i++
			continue
		}
		b.WriteByte(v[i])
	}
	return b.String()
}
