package hec

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"quetzalog/internal/ingestion"
	"quetzalog/pkg/event"
	"strings"
	"time"
)

const (
	hecSuccessText   = "OK"
	hecAuthError     = 6
	hecInvalidFormat = 7
	hecBadRequest    = 4
)

// Handler handles Splunk HEC-compatible ingestion requests.
type Handler struct {
	pipeline *ingestion.Pipeline
	tokens   map[string]string // token -> metadata (description)
	logger   *slog.Logger
}

// HECEvent represents a single HEC event payload.
type HECEvent struct {
	Time    any            `json:"time"`
	Host    string         `json:"host"`
	Source  string         `json:"source"`
	SourceT string         `json:"sourcetype"`
	Index   string         `json:"index"`
	Event   map[string]any `json:"event"`
	Raw     string         `json:"raw"`
}

// HECBatch represents a batch of HEC events.
type HECBatch struct {
	Events []HECEvent `json:"events"`
}

// HECResponse is the standard HEC success response.
type HECResponse struct {
	Text string `json:"text"`
	Code int    `json:"code"`
}

// HECError is the standard HEC error response.
type HECError struct {
	Text string `json:"text"`
	Code int    `json:"code"`
}

func (e *HECError) Error() string {
	return fmt.Sprintf("hec error %d: %s", e.Code, e.Text)
}

// HECToken represents a registered HEC authentication token.
type HECToken struct {
	ID    string
	Token string
	Meta  string // arbitrary metadata description
}

// NewHandler creates a new HEC ingestion handler with the given tokens.
func NewHandler(pipeline *ingestion.Pipeline, tokens []HECToken, logger *slog.Logger) *Handler {
	tokenMap := make(map[string]string, len(tokens))
	for _, t := range tokens {
		tokenMap[t.Token] = t.Meta
	}
	return &Handler{
		pipeline: pipeline,
		tokens:   tokenMap,
		logger:   logger,
	}
}

// Handle processes HEC ingestion requests. Routes between /services/collector,
// /services/collector/event, and /services/collector/raw.
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		hecErr(w, fmt.Sprintf("method %s not allowed", r.Method), http.StatusBadRequest)
		return nil
	}

	token, err := h.extractToken(r)
	if err != nil {
		hecErr(w, err.Error(), http.StatusUnauthorized)
		return nil
	}

	path := r.URL.Path

	// /services/collector/raw
	if strings.HasSuffix(path, "/raw") {
		return h.handleRaw(w, r, token)
	}

	// /services/collector and /services/collector/event
	var result HECResponse
	if path == "/services/collector" || strings.HasSuffix(path, "/event") {
		result, err = h.handleEvent(w, r, token)
		if err != nil {
			hecErr(w, err.Error(), http.StatusBadRequest)
			return nil
		}
	} else {
		hecErr(w, "unknown endpoint", http.StatusBadRequest)
		return nil
	}

	writeHECJSON(w, result)
	return nil
}

// extractToken retrieves the HEC token from the Authorization header or query parameter.
func (h *Handler) extractToken(r *http.Request) (string, error) {
	// Check Authorization header first
	auth := r.Header.Get("Authorization")
	if auth != "" {
		if strings.HasPrefix(auth, "Splunk ") {
			token := strings.TrimPrefix(auth, "Splunk ")
			if _, valid := h.tokens[token]; !valid {
				return "", &HECError{Text: "Invalid authentication token", Code: hecAuthError}
			}
			return token, nil
		}
		// Non-Splunk auth header but still present - could be a token directly
		if strings.Contains(auth, " ") {
			// Try the part after "Splunk "
			parts := strings.SplitN(auth, " ", 2)
			if len(parts) == 2 {
				if _, valid := h.tokens[parts[1]]; !valid {
					return "", &HECError{Text: "Invalid authentication token", Code: hecAuthError}
				}
				return parts[1], nil
			}
		}
	}

	// Fall back to query parameter
	if token := r.URL.Query().Get("token"); token != "" {
		if _, valid := h.tokens[token]; !valid {
			return "", &HECError{Text: "Invalid authentication token", Code: hecAuthError}
		}
		return token, nil
	}

	return "", &HECError{Text: "Authentication token required", Code: hecAuthError}
}

// handleEvent processes HEC event ingestion (single or batch).
func (h *Handler) handleEvent(w http.ResponseWriter, r *http.Request, token string) (HECResponse, error) {
	body, err := readHECBody(r)
	if err != nil {
		return HECResponse{}, &HECError{Text: "Failed to read request body", Code: hecBadRequest}
	}

	// Determine if batch or single event
	var hhecResp HECResponse

	if isHECBatch(body) {
		hhecResp, err = h.handleHECBatch(body, r, token)
		if err != nil {
			return HECResponse{}, err
		}
	} else {
		hhecResp, err = h.handleHECSingle(body, r, token)
		if err != nil {
			return HECResponse{}, err
		}
	}

	return hhecResp, nil
}

// handleHECSingle processes a single HEC event.
func (h *Handler) handleHECSingle(body []byte, r *http.Request, token string) (HECResponse, error) {
	var hecEvent HECEvent
	if err := json.Unmarshal(body, &hecEvent); err != nil {
		// Try as raw event (just the event object)
		var rawEvent map[string]any
		if err2 := json.Unmarshal(body, &rawEvent); err2 == nil {
			hecEvent.Event = rawEvent
		} else {
			return HECResponse{}, &HECError{Text: "Invalid HEC event format", Code: hecInvalidFormat}
		}
	}

	ev := hhecToEvent(hecEvent)
	ev.ReceivedAt = time.Now()

	ctx := r.Context()
	if err := h.pipeline.Ingest(ctx, ev); err != nil {
		h.logger.Warn("HEC ingest failed", "error", err)
		return HECResponse{}, &HECError{Text: fmt.Sprintf("Event ingestion failed: %s", err.Error()), Code: hecInvalidFormat}
	}

	h.logger.Info("HEC event ingested", "token", token, "host", hecEvent.Host, "source", hecEvent.Source)
	return HECResponse{Text: hecSuccessText, Code: 0}, nil
}

// handleHECBatch processes a batch of HEC events.
func (h *Handler) handleHECBatch(body []byte, r *http.Request, token string) (HECResponse, error) {
	var batch HECBatch
	if err := json.Unmarshal(body, &batch); err != nil {
		return HECResponse{}, &HECError{Text: "Invalid HEC batch format", Code: hecInvalidFormat}
	}

	if len(batch.Events) == 0 {
		return HECResponse{}, &HECError{Text: "No events in batch", Code: hecBadRequest}
	}

	var successCount int
	var errorMessages []string

	for i, hecEvent := range batch.Events {
		ev := hhecToEvent(hecEvent)
		ev.ReceivedAt = time.Now()

		ctx := r.Context()
		if err := h.pipeline.Ingest(ctx, ev); err != nil {
			h.logger.Warn("HEC batch event failed", "index", i, "error", err)
			errorMessages = append(errorMessages, fmt.Sprintf("event[%d]: %s", i, err.Error()))
		} else {
			successCount++
		}
	}

	if successCount == 0 && len(errorMessages) > 0 {
		return HECResponse{}, &HECError{Text: strings.Join(errorMessages, "; "), Code: hecInvalidFormat}
	}

	h.logger.Info("HEC batch ingested", "token", token, "count", len(batch.Events), "success", successCount)
	return HECResponse{Text: hecSuccessText, Code: 0}, nil
}

// handleRaw processes raw text ingestion via /services/collector/raw.
func (h *Handler) handleRaw(w http.ResponseWriter, r *http.Request, token string) error {
	body, err := readHECBody(r)
	if err != nil {
		hecErr(w, "Failed to read request body", http.StatusBadRequest)
		return nil
	}

	if len(body) == 0 {
		hecErr(w, "Empty request body", http.StatusBadRequest)
		return nil
	}

	ev := event.NewEvent()
	ev.Message = string(body)
	ev.Raw = body
	ev.RawFormat = "raw"
	ev.SourceType = "hec_raw"
	ev.Source = "hec_raw_ingest"
	ev.ReceivedAt = time.Now()

	ctx := r.Context()
	if err := h.pipeline.Ingest(ctx, ev); err != nil {
		h.logger.Warn("HEC raw ingest failed", "error", err)
		hecErr(w, fmt.Sprintf("Event ingestion failed: %s", err.Error()), http.StatusBadRequest)
		return nil
	}

	h.logger.Info("HEC raw event ingested", "token", token, "length", len(body))
	hecJSON(w, HECResponse{Text: hecSuccessText, Code: 0})
	return nil
}

// hhecToEvent converts a HECEvent to an event.Event.
func hhecToEvent(hec HECEvent) *event.Event {
	ev := event.NewEvent()

	// Parse time if provided
	if hec.Time != nil {
		switch t := hec.Time.(type) {
		case float64:
			secs := int64(t)
			nanos := int64((t - float64(secs)) * 1e9)
			ev.Timestamp = time.Unix(secs, nanos)
		case string:
			ev.Timestamp = event.ParseTimestamp(t)
		case json.Number:
			if f, err := t.Float64(); err == nil {
				secs := int64(f)
				nanos := int64((f - float64(secs)) * 1e9)
				ev.Timestamp = time.Unix(secs, nanos)
			}
		}
	}

	// HEC event payload goes into both the message and attributes
	if len(hec.Event) > 0 {
		if msg, ok := hec.Event["message"].(string); ok {
			ev.Message = msg
		} else if msg, ok := hec.Event["message"]; ok {
			ev.Message = fmt.Sprintf("%v", msg)
		}

		// Map HEC event fields to event attributes
		ev.Attributes = make(map[string]any)
		for k, v := range hec.Event {
			ev.Attributes[k] = v
		}
	} else if hec.Raw != "" {
		ev.Message = hec.Raw
	}

	// HEC metadata
	if hec.Host != "" {
		ev.Host = hec.Host
	}
	if hec.Source != "" {
		ev.Source = hec.Source
	}
	if hec.SourceT != "" {
		ev.SourceType = hec.SourceT
	}
	if hec.Index != "" {
		ev.Service = hec.Index
	}

	return ev
}

// isHECBatch checks if the body is a HEC batch (has "events" key with array value).
func isHECBatch(body []byte) bool {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return false
	}
	eventsRaw, ok := raw["events"]
	if !ok {
		return false
	}
	var arr []json.RawMessage
	return json.Unmarshal(eventsRaw, &arr) == nil
}

func readHECBody(r *http.Request) ([]byte, error) {
	const maxHECBody = 10 * 1024 * 1024
	br := http.MaxBytesReader(nil, r.Body, maxHECBody)
	body, err := io.ReadAll(br)
	if err != nil {
		return nil, fmt.Errorf("request body too large or unreadable: %w", err)
	}
	if len(body) > maxHECBody {
		return nil, fmt.Errorf("request body exceeds %d byte limit", maxHECBody)
	}
	return body, nil
}

// hecJSON writes a HEC-formatted JSON response.
func hecJSON(w http.ResponseWriter, resp HECResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// hecErr writes a HEC-formatted error response.
func hecErr(w http.ResponseWriter, msg string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	errResp := HECError{Text: msg, Code: statusCode}
	json.NewEncoder(w).Encode(errResp)
}

// writeHECJSON writes a HEC success response.
func writeHECJSON(w http.ResponseWriter, resp HECResponse) {
	hecJSON(w, resp)
}
