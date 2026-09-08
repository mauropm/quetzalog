package event

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Event represents a canonical log/security event in the SIEM pipeline.
type Event struct {
	ID              string         `json:"id"`
	Timestamp       time.Time      `json:"timestamp"`
	ReceivedAt      time.Time      `json:"received_at"`
	Source          string         `json:"source,omitempty"`
	SourceType      string         `json:"source_type,omitempty"`
	Host            string         `json:"host,omitempty"`
	IP              string         `json:"ip,omitempty"`
	Service         string         `json:"service,omitempty"`
	Application     string         `json:"application,omitempty"`
	Severity        string         `json:"severity,omitempty"`
	Message         string         `json:"message"`
	EventType       string         `json:"event_type,omitempty"`
	Category        string         `json:"category,omitempty"`
	Action          string         `json:"action,omitempty"`
	Outcome         string         `json:"outcome,omitempty"`
	User            string         `json:"user,omitempty"`
	UserID          string         `json:"user_id,omitempty"`
	Process         string         `json:"process,omitempty"`
	ProcessID       string         `json:"process_id,omitempty"`
	ParentPID       string         `json:"parent_pid,omitempty"`
	FilePath        string         `json:"file_path,omitempty"`
	DestinationIP   string         `json:"destination_ip,omitempty"`
	DestinationPort int            `json:"destination_port,omitempty"`
	SourceIP        string         `json:"source_ip,omitempty"`
	SourcePort      int            `json:"source_port,omitempty"`
	Attributes      map[string]any `json:"attributes,omitempty"`
	Raw             []byte         `json:"-"`
	RawFormat       string         `json:"raw_format,omitempty"`
	TraceID         string         `json:"trace_id,omitempty"`
	SpanID          string         `json:"span_id,omitempty"`
}

// NewEvent creates a new Event with a generated ID and current timestamps.
func NewEvent() *Event {
	return &Event{
		ID:         GenerateEventID(),
		Timestamp:  time.Now(),
		ReceivedAt: time.Now(),
		Attributes: make(map[string]any),
	}
}

// EventFromJSON parses a JSON byte slice into an Event.
func EventFromJSON(data []byte) (*Event, error) {
	var e Event
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("failed to unmarshal event JSON: %w", err)
	}

	if e.ID == "" {
		e.ID = GenerateEventID()
	}

	if e.ReceivedAt.IsZero() {
		e.ReceivedAt = time.Now()
	}

	if e.Attributes == nil {
		e.Attributes = make(map[string]any)
	}

	return &e, nil
}

// EventToJSON serializes an Event to a JSON byte slice.
func EventToJSON(e *Event) ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("cannot marshal nil event")
	}
	data, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal event to JSON: %w", err)
	}
	return data, nil
}

// EventToMap converts an Event to a flat map for database storage.
func EventToMap(e *Event) map[string]any {
	if e == nil {
		return nil
	}

	result := map[string]any{
		"id":               e.ID,
		"timestamp":        e.Timestamp.UTC(),
		"received_at":      e.ReceivedAt.UTC(),
		"source":           e.Source,
		"source_type":      e.SourceType,
		"host":             e.Host,
		"ip":               e.IP,
		"service":          e.Service,
		"application":      e.Application,
		"severity":         ParseSeverity(e.Severity),
		"message":          e.Message,
		"event_type":       e.EventType,
		"category":         e.Category,
		"action":           e.Action,
		"outcome":          e.Outcome,
		"user":             e.User,
		"user_id":          e.UserID,
		"process":          e.Process,
		"process_id":       e.ProcessID,
		"parent_pid":       e.ParentPID,
		"file_path":        e.FilePath,
		"destination_ip":   e.DestinationIP,
		"destination_port": e.DestinationPort,
		"source_ip":        e.SourceIP,
		"source_port":      e.SourcePort,
		"raw_format":       e.RawFormat,
		"trace_id":         e.TraceID,
		"span_id":          e.SpanID,
	}

	attrs := e.Attributes
	if attrs == nil {
		attrs = make(map[string]any)
	}
	if data, err := json.Marshal(attrs); err == nil {
		result["attributes"] = string(data)
	}
	for k, v := range e.Attributes {
		result["attr."+k] = v
	}

	if e.Raw != nil {
		result["raw"] = string(e.Raw)
	}

	return result
}

// EventsToList converts a slice of Event pointers to a slice of maps.
func EventsToList(events []*Event) []map[string]any {
	if events == nil {
		return nil
	}

	result := make([]map[string]any, 0, len(events))
	for _, e := range events {
		result = append(result, EventToMap(e))
	}
	return result
}

// ParseSeverity normalizes a severity string to a canonical form.
// Supported values: debug, info, notice, warning, warn, err, error, critical, crit, alert, emergency, emerg.
func ParseSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))

	switch s {
	case "debug", "dbg", "0":
		return "debug"
	case "info", "informational", "1":
		return "info"
	case "notice", "2":
		return "notice"
	case "warning", "warn", "3":
		return "warning"
	case "err", "error", "4":
		return "err"
	case "critical", "crit", "5":
		return "critical"
	case "alert", "6":
		return "alert"
	case "emergency", "emerg", "7", "panic":
		return "emergency"
	default:
		return s
	}
}

// severityRank returns a numeric rank for a severity string for comparison purposes.
func severityRank(s string) int {
	switch s {
	case "debug":
		return 0
	case "info":
		return 1
	case "notice":
		return 2
	case "warning":
		return 3
	case "err":
		return 4
	case "critical":
		return 5
	case "alert":
		return 6
	case "emergency":
		return 7
	default:
		return -1
	}
}

// ParseTimestamp attempts to parse a timestamp string using multiple common formats.
func ParseTimestamp(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}

	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000Z07:00",
		"2006-01-02T15:04:05.000000Z07:00",
		"2006-01-02T15:04:05.000Z07:00",
		"2006-01-02T15:04:05Z0700",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.000",
		"2006-01-02 15:04:05.000000",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05.000000-07:00",
		"02 Jan 2006 15:04:05 MST",
		"02/Jan/2006:15:04:05 -0700",
		time.RFC1123,
		time.RFC1123Z,
		time.RFC822,
		time.RFC822Z,
		"20060102150405",
	}

	for _, layout := range formats {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}

	// Try parsing as a Unix timestamp (integer or float)
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		secs := int64(f)
		nanos := int64((f - float64(secs)) * 1e9)
		return time.Unix(secs, nanos)
	}

	return time.Time{}
}

// GenerateEventID generates a UUID v4 identifier.
func GenerateEventID() string {
	return uuid.New().String()
}
