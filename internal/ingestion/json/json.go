package json

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"quetzalog/internal/ingestion"
	"quetzalog/pkg/event"
	"time"
)

// IngestHandler handles HTTP POST requests for ingesting events in JSON format.
type IngestHandler struct {
	pipeline *ingestion.Pipeline
	logger   *slog.Logger
}

// RequestBody represents the fields of a single event in a JSON ingestion request.
type RequestBody struct {
	Timestamp  string         `json:"timestamp"`
	Source     string         `json:"source"`
	SourceType string         `json:"sourcetype"`
	Host       string         `json:"host"`
	Service    string         `json:"service"`
	Severity   string         `json:"severity"`
	EventType  string         `json:"event_type"`
	Category   string         `json:"category"`
	Action     string         `json:"action"`
	Outcome    string         `json:"outcome"`
	User       string         `json:"user"`
	SourceIP   string         `json:"source_ip"`
	Message    string         `json:"message"`
	Attributes map[string]any `json:"attributes"`
}

// BatchRequestBody represents a batch of events in a JSON ingestion request.
type BatchRequestBody struct {
	Events []RequestBody `json:"events"`
}

// IngestResponse is the JSON response for an ingestion request.
type IngestResponse struct {
	Accepted int64   `json:"accepted"`
	Rejected int64   `json:"rejected"`
	Errors   []Error `json:"errors"`
}

// Error represents a single error in an ingestion response.
type Error struct {
	Index int    `json:"index"`
	Error string `json:"error"`
}

// NewIngestHandler creates a new JSON ingestion handler.
func NewIngestHandler(pipeline *ingestion.Pipeline, logger *slog.Logger) *IngestHandler {
	return &IngestHandler{
		pipeline: pipeline,
		logger:   logger,
	}
}

// Handle dispatches the request to single or batch handlers based on the body format.
func (h *IngestHandler) Handle(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
	}

	body, err := readBody(r)
	if err != nil {
		return errorResponse(w, http.StatusBadRequest, "failed to read request body: "+err.Error())
	}

	// Determine if it's a batch or single event by looking for "events" key.
	if isBatch(body) {
		return h.handleBatch(body, w, r)
	}

	return h.handleSingle(body, w, r)
}

// handleSingle processes a single event ingestion request.
func (h *IngestHandler) handleSingle(body []byte, w http.ResponseWriter, r *http.Request) error {
	var req RequestBody
	if err := json.Unmarshal(body, &req); err != nil {
		return errorResponse(w, http.StatusBadRequest, "invalid request body: "+err.Error())
	}

	ev := h.parseEvent(req)
	ev.ReceivedAt = time.Now()

	ctx := r.Context()
	if err := h.pipeline.Ingest(ctx, ev); err != nil {
		h.logger.Warn("failed to ingest event", "error", err)
		resp := IngestResponse{Accepted: 0, Rejected: 1, Errors: []Error{{Index: 0, Error: err.Error()}}}
		return writeJSON(w, http.StatusAccepted, resp)
	}

	resp := IngestResponse{Accepted: 1, Rejected: 0}
	return writeJSON(w, http.StatusAccepted, resp)
}

// handleBatch processes a batch event ingestion request.
func (h *IngestHandler) handleBatch(body []byte, w http.ResponseWriter, r *http.Request) error {
	var req BatchRequestBody
	if err := json.Unmarshal(body, &req); err != nil {
		return errorResponse(w, http.StatusBadRequest, "invalid request body: "+err.Error())
	}

	if len(req.Events) == 0 {
		return errorResponse(w, http.StatusBadRequest, "no events in batch")
	}

	ctx := r.Context()
	accepted := int64(0)
	rejected := int64(0)
	var errs []Error

	for i, ev := range req.Events {
		event := h.parseEvent(ev)
		event.ReceivedAt = time.Now()

		if err := h.pipeline.Ingest(ctx, event); err != nil {
			rejected++
			errs = append(errs, Error{Index: i, Error: err.Error()})
		} else {
			accepted++
		}
	}

	resp := IngestResponse{Accepted: accepted, Rejected: rejected, Errors: errs}
	return writeJSON(w, http.StatusAccepted, resp)
}

// parseEvent converts a RequestBody into an event.Event.
func (h *IngestHandler) parseEvent(body RequestBody) *event.Event {
	ev := event.NewEvent()

	if body.Timestamp != "" {
		ev.Timestamp = event.ParseTimestamp(body.Timestamp)
	}

	ev.Source = body.Source
	ev.SourceType = body.SourceType
	ev.Host = body.Host
	ev.Service = body.Service
	ev.Severity = event.ParseSeverity(body.Severity)
	ev.EventType = body.EventType
	ev.Category = body.Category
	ev.Action = body.Action
	ev.Outcome = body.Outcome
	ev.User = body.User
	ev.SourceIP = body.SourceIP
	ev.Message = body.Message

	if len(body.Attributes) > 0 {
		ev.Attributes = body.Attributes
	}

	return ev
}

// readBody reads the request body with a size limit.
func readBody(r *http.Request) ([]byte, error) {
	const maxBody = 10 * 1024 * 1024
	r.Body = http.MaxBytesReader(nil, r.Body, maxBody)
	body, err := io.ReadAll(r.Body)
	_ = r.Body
	return body, err
}

// isBatch checks if the JSON body contains an "events" array at the top level.
func isBatch(body []byte) bool {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return false
	}
	_, hasEvents := raw["events"]
	return hasEvents
}

func errorResponse(w http.ResponseWriter, code int, reason string) error {
	err := &IngestError{StatusCode: code, Reason: reason}
	_ = writeJSON(w, code, map[string]string{"error": reason})
	return err
}

// IngestError represents an error with an HTTP status code for the ingestion handler.
type IngestError struct {
	StatusCode int
	Reason     string
}

func (e *IngestError) Error() string {
	return fmt.Sprintf("ingest error %d: %s", e.StatusCode, e.Reason)
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}
