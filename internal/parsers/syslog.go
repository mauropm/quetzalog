package parsers

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"quetzalog/pkg/event"
)

var re3164 = regexp.MustCompile(
	`^<(\d{1,3})>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)`,
)

// RFC5424: PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP
// MSGID SP [SD] MSG. A bare "-" in a field means "no value"; when
// structured data is absent, the SD position holds "-".
var re5424Prefix = regexp.MustCompile(
	`^<(\d{1,3})>1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$`,
)

// re5424MsgidPID matches the non-standard "ID[pid]" msgid form where the
// process id is carried in brackets.
var re5424MsgidPID = regexp.MustCompile(`^(.+)\[(\d+)\]$`)

type syslog3164Parser struct{}

func (syslog3164Parser) Name() string    { return "syslog3164" }
func (syslog3164Parser) Version() string { return "1" }

func (syslog3164Parser) Parse(raw []byte) (*Parsed, bool) {
	msg := string(raw)
	m := re3164.FindStringSubmatch(msg)
	if m == nil {
		return nil, false
	}
	out := &Parsed{}
	fillPriority(out, m[1])

	// RFC3164 timestamps carry no year; Go parses them in year 0. Re-base
	// to the current year by reconstructing the date.
	t := parseTimestamp(m[2])
	if !t.IsZero() {
		year, _, _ := time.Now().Date()
		out.Timestamp = time.Date(year, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
	}

	if m[3] != "" && m[3] != "-" {
		out.Host = m[3]
	}
	if m[4] != "" && m[4] != "-" {
		out.Source = m[4]
	}
	if m[5] != "" {
		out.ProcessID = m[5]
		out.Attrs()["pid"] = m[5]
	}
	if m[6] != "" && m[6] != "-" {
		out.Message = m[6]
	}
	return out, true
}

type syslog5424Parser struct{}

func (syslog5424Parser) Name() string    { return "syslog5424" }
func (syslog5424Parser) Version() string { return "1" }

func (syslog5424Parser) Parse(raw []byte) (*Parsed, bool) {
	msg := string(raw)
	m := re5424Prefix.FindStringSubmatch(msg)
	if m == nil {
		return nil, false
	}
	out := &Parsed{}
	fillPriority(out, m[1])

	if m[2] != "-" {
		out.Timestamp = parseTimestamp(m[2])
	}
	if m[3] != "" && m[3] != "-" {
		out.Host = m[3]
	}
	if m[4] != "" && m[4] != "-" {
		out.Source = m[4]
	}
	if m[5] != "" && m[5] != "-" {
		out.ProcessID = m[5]
		out.Attrs()["pid"] = m[5]
	}
	if m[6] != "" && m[6] != "-" {
		out.Attrs()["msgid"] = m[6]
		// Non-standard "ID[pid]" msgid form carries the process id.
		if b := re5424MsgidPID.FindStringSubmatch(m[6]); b != nil {
			out.Attrs()["pid"] = b[2]
			if out.ProcessID == "" {
				out.ProcessID = b[2]
			}
		}
	}

	// m[7] is the remainder: "-", "- MSG", "<SD> MSG", or "MSG".
	rest := m[7]
	if rest == "-" {
		rest = ""
	} else if strings.HasPrefix(rest, "- ") {
		rest = rest[2:]
	}
	elems, message := splitStructuredData(rest)
	if len(elems) > 0 {
		out.Attrs()["sdid"] = elems[0].ID
	}
	for _, e := range elems {
		for k, v := range e.Params {
			out.Attrs()["sd."+e.ID+"."+k] = v
		}
	}
	if message != "" && message != "-" {
		out.Message = message
	}
	return out, true
}

// sdElement is one structured-data element in document order.
type sdElement struct {
	ID     string
	Params map[string]string
}

// splitStructuredData splits the post-msgid remainder of an RFC5424 message
// into structured-data elements (in document order) and the free-form
// message that follows them.
func splitStructuredData(rest string) ([]sdElement, string) {
	var elems []sdElement
	s := rest

	for {
		trimmed := strings.TrimLeft(s, " ")
		if !strings.HasPrefix(trimmed, "<") {
			break
		}
		end := strings.IndexByte(trimmed, '>')
		if end < 0 {
			// Unterminated element: treat the rest as message.
			break
		}
		id, params := parseSDElement(trimmed[1:end])
		if id != "" {
			elems = append(elems, sdElement{ID: id, Params: params})
		}
		s = trimmed[end+1:]
	}
	return elems, strings.TrimLeft(s, " ")
}

// parseSDElement parses one structured-data element body:
// "id k="v" k2=v". Quoted values may contain spaces. Element ids keep
// their local-facility suffix ("id@42") as-is.
func parseSDElement(body string) (string, map[string]string) {
	params := map[string]string{}
	id := body
	rest := ""
	if sp := strings.IndexByte(body, ' '); sp >= 0 {
		id = body[:sp]
		rest = body[sp+1:]
	}
	for {
		rest = strings.TrimLeft(rest, " ")
		if rest == "" {
			break
		}
		eq := strings.IndexByte(rest, '=')
		if eq <= 0 {
			break
		}
		key := rest[:eq]
		val := rest[eq+1:]
		if strings.HasPrefix(val, `"`) {
			end := -1
			for j := 1; j < len(val); j++ {
				if val[j] == '"' && val[j-1] != '\\' {
					end = j
					break
				}
			}
			if end < 0 {
				break
			}
			params[key] = val[1:end]
			rest = val[end+1:]
			continue
		}
		sp := strings.IndexByte(val, ' ')
		if sp < 0 {
			params[key] = val
			break
		}
		params[key] = val[:sp]
		rest = val[sp+1:]
	}
	return id, params
}

// fillPriority derives severity (and facility attributes) from a syslog
// priority value.
func fillPriority(out *Parsed, pri string) {
	p, err := strconv.Atoi(pri)
	if err != nil {
		return
	}
	out.Attrs()["priority"] = p
	out.Attrs()["facility"] = facilityName(p / 8)
	out.Severity = severityName(p % 8)
}

func facilityName(code int) string {
	facilities := []string{
		"kernel", "user-level", "mail", "daemon",
		"auth", "syslog", "line printer", "news",
		"uucp", "cron", "authpriv", "ftp",
		"ntp", "audit", "alert", "clock",
		"local0", "local1", "local2", "local3",
		"local4", "local5", "local6", "local7",
	}
	if code < 0 || code > 23 {
		return "unknown"
	}
	return facilities[code]
}

func severityName(code int) string {
	severities := []string{
		"emergency", "alert", "critical", "error",
		"warning", "notice", "informational", "debug",
	}
	if code < 0 || code > 7 {
		return "unknown"
	}
	return severities[code]
}

// parseTimestamp handles syslog timestamp shapes: RFC3164
// ("Sep  3 18:30:00", no year) and RFC5424 (RFC3339, via pkg/event).
func parseTimestamp(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse("Jan _2 15:04:05", s); err == nil {
		return t
	}
	return event.ParseTimestamp(s)
}

type plainParser struct{}

func (plainParser) Name() string    { return "plain" }
func (plainParser) Version() string { return "1" }

func (plainParser) Parse(raw []byte) (*Parsed, bool) {
	msg := strings.TrimSpace(string(raw))
	return &Parsed{Message: msg}, true
}
