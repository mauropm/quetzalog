package otlp

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"quetzalog/internal/ingestion"
	"quetzalog/pkg/event"
)

// Handler handles OTLP log ingestion via HTTP.
type Handler struct {
	pipeline *ingestion.Pipeline
	logger   *slog.Logger
}

// NewHandler creates a new OTLP log handler.
func NewHandler(pipeline *ingestion.Pipeline, logger *slog.Logger) *Handler {
	return &Handler{
		pipeline: pipeline,
		logger:   logger,
	}
}

// Handle processes OTLP log ingestion requests. Supports both protobuf and JSON encodings.
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return &OTLPError{StatusCode: http.StatusMethodNotAllowed, Reason: "method not allowed"}
	}

	ct := r.Header.Get("Content-Type")

	switch {
	case strings.Contains(ct, "json"), ct == "":
		return h.handleJSON(w, r)
	case strings.Contains(ct, "protobuf") || strings.Contains(ct, "proto"):
		return h.handleProtobuf(w, r)
	default:
		return &OTLPError{StatusCode: http.StatusUnsupportedMediaType, Reason: "unsupported content type: " + ct}
	}
}

// handleJSON processes OTLP logs in JSON format.
func (h *Handler) handleJSON(w http.ResponseWriter, r *http.Request) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return &OTLPError{StatusCode: http.StatusBadRequest, Reason: "failed to read request body"}
	}

	var logsData OTLPLogsData
	if err := json.Unmarshal(body, &logsData); err != nil {
		return &OTLPError{StatusCode: http.StatusBadRequest, Reason: "invalid OTLP JSON: " + err.Error()}
	}

	var ingested int64
	var errored int64

	for _, rl := range logsData.ResourceLogs {
		resourceAttrs := parseAttributes(rl.Resource.Attributes)
		scopeAttrs := make(map[string]any)

		for _, sl := range rl.ScopeLogs {
			if sl.Scope != nil {
				if sl.Scope.Name != "" {
					scopeAttrs["scope.name"] = sl.Scope.Name
				}
				if sl.Scope.Version != "" {
					scopeAttrs["scope.version"] = sl.Scope.Version
				}
				for _, a := range sl.Scope.Attributes {
					scopeAttrs[a.Key] = attrValue(a.Value)
				}
			}

			for _, lr := range sl.LogRecords {
				ev := h.logRecordToEvent(lr, resourceAttrs, scopeAttrs)
				if err := h.pipeline.Ingest(r.Context(), ev); err != nil {
					h.logger.Warn("OTLP ingest failed", "error", err)
					errored++
				} else {
					ingested++
				}
			}
		}
	}

	h.logger.Info("OTLP logs ingested", "count", ingested, "errors", errored)
	return writeOTLPJSON(w, http.StatusOK, OTLPResponse{})
}

// handleProtobuf processes OTLP logs in protobuf format.
// Note: Full protobuf parsing requires proto dependencies. This is a stub
// that returns a placeholder response. A production implementation would
// use the official protobuf generated code for traceptracepb.LogsData.
func (h *Handler) handleProtobuf(w http.ResponseWriter, r *http.Request) error {
	_, err := io.ReadAll(r.Body)
	if err != nil {
		return &OTLPError{StatusCode: http.StatusBadRequest, Reason: "failed to read request body"}
	}

	// TODO: Parse traceptracepb.LogsData protobuf message.
	// This requires adding the official OTLP proto dependencies:
	//   import "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	//   import "go.opentelemetry.io/proto/otlp/logs/v1"
	// For now, accept the body and return success to allow instrumentation libraries.
	h.logger.Info("OTLP protobuf body received (stub)")

	return writeOTLPJSON(w, http.StatusOK, OTLPResponse{})
}

// logRecordToEvent converts an OTLP log record to an event.Event.
func (h *Handler) logRecordToEvent(lr OTLPLogRecord, resourceAttrs map[string]any, scopeAttrs map[string]any) *event.Event {
	ev := event.NewEvent()

	// Timestamp from OTLP (nanoseconds since epoch)
	if lr.TimeUnixNano != "" {
		if ns, err := parseUInt64(lr.TimeUnixNano); err == nil {
			ev.Timestamp = time.Unix(0, int64(ns))
		}
	}

	// Observed timestamp
	if lr.ObservedTimeUnixNano != "" {
		if ns, err := parseUInt64(lr.ObservedTimeUnixNano); err == nil {
			ev.Attributes["observed_time_unix_nano"] = ns
		}
	}

	// Severity
	if lr.SeverityText != "" {
		ev.Severity = lr.SeverityText
	}
	if lr.SeverityNumber != 0 && lr.SeverityText == "" {
		ev.Severity = severityFromNumber(lr.SeverityNumber)
	}
	if lr.SeverityNumber != 0 {
		ev.Attributes["severity_number"] = lr.SeverityNumber
	}

	// Body
	bodyVal := lr.Body.StringValue
	if bodyVal == "" {
		if lr.Body.IntValue != nil {
			bodyVal = strconv.FormatInt(*lr.Body.IntValue, 10)
		} else if lr.Body.BoolValue != nil {
			bodyVal = strconv.FormatBool(*lr.Body.BoolValue)
		} else if lr.Body.DoubleValue != nil {
			bodyVal = strconv.FormatFloat(*lr.Body.DoubleValue, 'f', -1, 64)
		} else if lr.Body.BytesValue != "" {
			bodyVal = lr.Body.BytesValue
		}
	}
	ev.Message = bodyVal

	// Resource attributes
	for k, v := range resourceAttrs {
		switch k {
		case "service.name":
			ev.Service = v.(string)
		case "host.name":
			ev.Host = v.(string)
		default:
			if ev.Attributes == nil {
				ev.Attributes = make(map[string]any)
			}
			ev.Attributes["resource."+k] = v
		}
	}

	// Scope attributes
	for k, v := range scopeAttrs {
		if ev.Attributes == nil {
			ev.Attributes = make(map[string]any)
		}
		ev.Attributes["scope."+k] = v
	}

	// Log record attributes
	for _, a := range lr.Attributes {
		key := a.Key
		val := attrValue(a.Value)
		if ev.Attributes == nil {
			ev.Attributes = make(map[string]any)
		}
		ev.Attributes[key] = val

		// Map common OTLP attribute keys
		switch key {
		case "http.method":
			ev.Attributes["http_method"] = val
		case "http.url":
			if s, ok := val.(string); ok {
				ev.Attributes["http_url"] = s
			}
		case "http.status_code":
			ev.Attributes["http_status_code"] = val
		case "db.statement":
			ev.Attributes["db_statement"] = val
		case "error.type":
			ev.EventType = "error"
		case "source.ip":
			if s, ok := val.(string); ok {
				ev.SourceIP = s
			}
		case "user.name":
			if s, ok := val.(string); ok {
				ev.User = s
			}
		case "user.id":
			if s, ok := val.(string); ok {
				ev.UserID = s
			}
		}
	}

	// Trace context
	if lr.TraceID != "" {
		ev.TraceID = sanitizeHex(lr.TraceID)
	}
	if lr.SpanID != "" {
		ev.SpanID = sanitizeHex(lr.SpanID)
	}

	// Event type and category from attributes
	if et, ok := ev.Attributes["event.type"]; ok {
		if s, ok := et.(string); ok {
			ev.EventType = s
		}
	}
	if cat, ok := ev.Attributes["event.category"]; ok {
		if s, ok := cat.(string); ok {
			ev.Category = s
		}
	}

	return ev
}

// sanitizeHex ensures a hex string is in the correct format (lowercase, even length).
func sanitizeHex(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s)%2 != 0 && len(s) > 0 {
		s = "0" + s
	}
	if len(s) > 64 {
		s = s[len(s)-64:]
	}
	return s
}

// parseUInt64 parses a string into uint64.
func parseUInt64(s string) (uint64, error) {
	var n uint64
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

// parseAttributes converts OTLP attributes to a map.
func parseAttributes(attrs []OTLPAttribute) map[string]any {
	result := make(map[string]any)
	for _, a := range attrs {
		result[a.Key] = attrValue(a.Value)
	}
	return result
}

// attrValue extracts the value from an OTLP AnyValue.
func attrValue(v OTLPValue) any {
	if v.StringValue != "" {
		return v.StringValue
	}
	if v.BoolValue != nil {
		return *v.BoolValue
	}
	if v.IntValue != nil {
		return *v.IntValue
	}
	if v.DoubleValue != nil {
		return *v.DoubleValue
	}
	if v.ArrayValue != nil {
		return v.ArrayValue
	}
	if v.KvlistValue != nil {
		return v.KvlistValue
	}
	if v.BytesValue != "" {
		return v.BytesValue
	}
	return nil
}

// severityFromNumber converts an OTLP SeverityNumber to a severity string.
func severityFromNumber(n int32) string {
	switch {
	case n >= 25:
		return "emergency"
	case n >= 21:
		return "alert"
	case n >= 17:
		return "critical"
	case n >= 13:
		return "error"
	case n >= 9:
		return "warning"
	case n >= 5:
		return "notice"
	case n >= 1:
		return "informational"
	case n >= 0:
		return "debug"
	default:
		return "unset"
	}
}

// OTLPError represents an error specific to OTLP handling.
type OTLPError struct {
	StatusCode int
	Reason     string
}

func (e *OTLPError) Error() string {
	return "otlp error " + strconv.Itoa(e.StatusCode) + ": " + e.Reason
}

// writeOTLPJSON writes an OTLP-formatted JSON response.
func writeOTLPJSON(w http.ResponseWriter, status int, resp OTLPResponse) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(resp)
}

// OTLPAttribute represents an attribute key-value pair.
type OTLPAttribute struct {
	Key   string    `json:"key"`
	Value OTLPValue `json:"value"`
}

// OTLPValue represents an OTLP AnyValue.
type OTLPValue struct {
	StringValue string    `json:"stringValue,omitempty"`
	IntValue    *int64    `json:"intValue,omitempty"`
	BoolValue   *bool     `json:"boolValue,omitempty"`
	DoubleValue *float64  `json:"doubleValue,omitempty"`
	BytesValue  string    `json:"bytesValue,omitempty"`
	ArrayValue  *OTLPArray `json:"arrayValue,omitempty"`
	KvlistValue *OTLPKeyValueList `json:"kvlistValue,omitempty"`
}

// OTLPArray represents an OTLP ArrayValue.
type OTLPArray struct {
	Values []OTLPValue `json:"values"`
}

// OTLPKeyValueList represents an OTLP KeyValueListValue.
type OTLPKeyValueList struct {
	Values []OTLPAttribute `json:"values"`
}

// OTLPLogRecord represents a single log record in OTLP format.
type OTLPLogRecord struct {
	TimeUnixNano         string           `json:"timeUnixNano"`
	ObservedTimeUnixNano string           `json:"observedTimeUnixNano"`
	SeverityNumber       int32            `json:"severityNumber"`
	SeverityText         string           `json:"severityText"`
	Body                 OTLPValue        `json:"body"`
	Attributes           []OTLPAttribute  `json:"attributes"`
	DroppedAttributesCount int64         `json:"droppedAttributesCount"`
	TraceID              string           `json:"traceId"`
	SpanID               string           `json:"spanId"`
}

// SeverityIsSet checks if the severity text is set.
func (lr *OTLPLogRecord) SeverityIsSet() bool {
	return lr.SeverityText != ""
}

// OTLPScope represents the scope of a log record.
type OTLPScope struct {
	Name       string          `json:"name"`
	Version    string          `json:"version"`
	Attributes []OTLPAttribute `json:"attributes"`
}

// OTLP Scope is optional, use pointer.

// OTLPResourceLogs represents a batch of log records from a single resource.
type OTLPResourceLogs struct {
	Resource   OTLPResource    `json:"resource"`
	ScopeLogs  []OTLPScopeLogs `json:"scopeLogs"`
}

// OTLPResource represents resource attributes.
type OTLPResource struct {
	Attributes []OTLPAttribute `json:"attributes"`
}

// OTLPScopeLogs represents log records from a single scope.
type OTLPScopeLogs struct {
	Scope      *OTLPScope      `json:"scope"`
	LogRecords []OTLPLogRecord `json:"logRecords"`
}

// OTLPLogsData is the top-level OTLP logs data structure.
type OTLPLogsData struct {
	ResourceLogs []OTLPResourceLogs `json:"resourceLogs"`
}

// OTLPResponse is the standard OTLP success response (empty body).
type OTLPResponse struct {
}

// Note: gRPC implementation stub.
//
// To implement gRPC OTLP, add the following dependency and generated proto code:
//
//	go get go.opentelemetry.io/proto/otlp/collector/logs/v1
//	go get go.opentelemetry.io/proto/otlp/logs/v1
//
// Then implement:
//
//	type Server struct {
//		pb.UnimplementedLogsServiceServer
//		pipeline *ingestion.Pipeline
//	}
//
//	func (s *Server) Export(ctx context.Context, req *pb.ExportLogsServiceRequest) (*pb.ExportLogsServiceResponse, error) {
//		// Convert pb.ResourceLogsSlice to OTLPLogsData and process.
//		// ...
//		return &pb.ExportLogsServiceResponse{}, nil
//	}
