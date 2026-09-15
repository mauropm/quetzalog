package parsers

import (
	"encoding/json"
	"strconv"
	"strings"

	"quetzalog/pkg/event"
)

// GELF (Graylog2 Extended Log Format) records are JSON objects:
//
//	{"version":"1.1","host":"h","short_message":"m","timestamp":1234.56,
//	 "_key":"value"}
//
// Reserved fields: version, host, short_message, full_message,
// file, line, level, timestamp. All other "_"-prefixed fields are
// custom and map to attributes.

type gelfParser struct{}

func (gelfParser) Name() string    { return "gelf" }
func (gelfParser) Version() string { return "1" }

func (gelfParser) Parse(raw []byte) (*Parsed, bool) {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, false
	}
	ver, _ := obj["version"].(string)
	if !strings.HasPrefix(ver, "1.") {
		return nil, false
	}
	// Require at least one GELF characteristic field so that arbitrary
	// JSON events are not swallowed by the GELF parser.
	characteristic := false
	for _, key := range []string{"short_message", "full_message", "host", "timestamp"} {
		if _, ok := obj[key]; ok {
			characteristic = true
			break
		}
	}
	if !characteristic {
		return nil, false
	}

	out := &Parsed{}
	if s, ok := obj["host"].(string); ok {
		out.Host = s
	}
	if s, ok := obj["short_message"].(string); ok {
		out.Message = s
	}
	if out.Message == "" {
		if s, ok := obj["full_message"].(string); ok {
			out.Message = s
		}
	}
	if f, ok := obj["timestamp"].(float64); ok {
		out.Timestamp = event.ParseTimestamp(strconv.FormatFloat(f, 'f', -1, 64))
	}
	for k, v := range obj {
		if !strings.HasPrefix(k, "_") {
			continue
		}
		sk := k[1:]
		switch sk {
		case "source":
			if s, ok := v.(string); ok {
				out.Source = s
			}
		default:
			out.Attrs()[sk] = v
		}
	}
	if out.Message == "" {
		out.Message = strings.TrimSpace(string(raw))
	}
	return out, true
}
