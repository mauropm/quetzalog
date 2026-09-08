package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"quetzalog/internal/alerts"
	"quetzalog/internal/auth"
	"quetzalog/internal/config"
	"quetzalog/internal/detections"
	"quetzalog/internal/events"
	"quetzalog/internal/incidents"
	"quetzalog/internal/query"
	"quetzalog/pkg/api"
	"quetzalog/pkg/event"
)

var validAttrKeyRe = regexp.MustCompile(`^[a-z0-9_]+$`)

// Hard caps for caller-supplied pagination to prevent unbounded result sets.
const (
	maxAPIPageLimit  = 1000
	maxAPIPageOffset = 1000000
)

// Handler wraps the dependencies for all HTTP API handlers.
type Handler struct {
	store          *events.Store
	alertStore     *alerts.Store
	incidentStore  *incidents.Store
	detectionStore *detections.Store
	authStore      *auth.Store
	searchSvc      *query.Service
	config         config.Config
	logger         *slog.Logger
}

// NewHandler creates a new API handler with the given configuration and dependencies.
func NewHandler(cfg config.Config, store *events.Store, searchSvc *query.Service, alertStore *alerts.Store, incidentStore *incidents.Store, detectionStore *detections.Store, authStore *auth.Store, logger *slog.Logger) *Handler {
	return &Handler{
		store:          store,
		alertStore:     alertStore,
		incidentStore:  incidentStore,
		detectionStore: detectionStore,
		authStore:      authStore,
		searchSvc:      searchSvc,
		config:         cfg,
		logger:         logger,
	}
}

// ─────────────────────────────────────────────
// Health & Stats
// ─────────────────────────────────────────────

// Health returns a 200 OK response to indicate the service is healthy.
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	api.WriteJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": "0.1.0",
		"uptime":  time.Since(startTime).String(),
	})
}

// Stats returns aggregate statistics about stored events.
func (h *Handler) Stats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	counts := map[string]any{
		"total": 0,
	}

	total, err := h.store.Count(ctx, events.Query{})
	if err != nil {
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError(fmt.Sprintf("failed to count events: %v", err)))
		return
	}
	counts["total"] = total

	severities := []string{"debug", "info", "notice", "warning", "err", "critical", "alert", "emergency"}
	countBySeverity := make(map[string]int)
	for _, sev := range severities {
		n, err := h.store.Count(ctx, events.Query{Severity: sev})
		if err != nil {
			h.logger.Error("count by severity", "severity", sev, "error", err)
			continue
		}
		countBySeverity[sev] = n
	}
	counts["by_severity"] = countBySeverity

	countBySource := make(map[string]int)
	{
		q := events.Query{Limit: 5000}
		sources, err := h.store.Search(ctx, q)
		if err != nil {
			h.logger.Error("list events for source stats", "error", err)
		} else {
			for _, e := range sources {
				countBySource[e.Source]++
			}
		}
	}
	counts["by_source"] = countBySource

	recentCount := 0
	recentStart := time.Now().Add(-24 * time.Hour)
	recentQ := events.Query{Start: recentStart}
	recentCount, err = h.store.Count(ctx, recentQ)
	if err != nil {
		h.logger.Error("count recent events", "error", err)
	}
	counts["recent_24h"] = recentCount

	api.WriteJSON(w, http.StatusOK, api.Success(counts))
}

// ─────────────────────────────────────────────
// Event Handlers
// ─────────────────────────────────────────────

// CreateEvent accepts a single event as JSON and persists it.
func (h *Handler) CreateEvent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("failed to read request body"))
		return
	}
	defer r.Body.Close()

	ev, err := event.EventFromJSON(body)
	if err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(fmt.Sprintf("invalid event JSON: %v", err)))
		return
	}

	if err := h.store.Create(ctx, ev); err != nil {
		h.logger.Error("create event", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to create event"))
		return
	}

	h.logger.Info("event created", "id", ev.ID, "source", ev.Source, "severity", ev.Severity)

	api.WriteJSON(w, http.StatusCreated, api.Success(ev))
}

// CreateBatchEvents accepts a list of events and persists them in a batch.
func (h *Handler) CreateBatchEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		Events []json.RawMessage `json:"events"`
	}

	if err := json.NewDecoder(io.LimitReader(r.Body, 50*1024*1024)).Decode(&req); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid batch request body"))
		return
	}

	if len(req.Events) == 0 {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("no events provided"))
		return
	}

	if len(req.Events) > 10000 {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("batch size exceeds maximum of 10000"))
		return
	}

	eventList := make([]*event.Event, 0, len(req.Events))
	for _, raw := range req.Events {
		ev, err := event.EventFromJSON(raw)
		if err != nil {
			api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(fmt.Sprintf("invalid event in batch: %v", err)))
			return
		}
		eventList = append(eventList, ev)
	}

	if err := h.store.CreateBatch(ctx, eventList); err != nil {
		h.logger.Error("create batch events", "count", len(eventList), "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to create batch events"))
		return
	}

	h.logger.Info("batch events created", "count", len(eventList))

	api.WriteJSON(w, http.StatusCreated, api.Success(map[string]any{
		"created": len(eventList),
	}))
}

// GetEvent retrieves a single event by its ID.
func (h *Handler) GetEvent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("missing event ID"))
		return
	}

	ev, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			api.WriteJSON(w, http.StatusNotFound, api.NotFound(fmt.Sprintf("event %s not found", id)))
			return
		}
		h.logger.Error("get event", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to retrieve event"))
		return
	}

	api.WriteJSON(w, http.StatusOK, api.Success(ev))
}

// DeleteEvent removes an event by its ID.
func (h *Handler) DeleteEvent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("missing event ID"))
		return
	}

	if err := h.store.DeleteByID(r.Context(), id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			api.WriteJSON(w, http.StatusNotFound, api.NotFound(fmt.Sprintf("event %s not found", id)))
			return
		}
		h.logger.Error("delete event", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to delete event"))
		return
	}

	h.logger.Info("event deleted", "id", id)
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"deleted": true}))
}

// ListEvents returns a paginated list of events with optional filters.
func (h *Handler) ListEvents(w http.ResponseWriter, r *http.Request) {
	q := events.NewQuery()

	q.Text = r.URL.Query().Get("q")
	q.Source = r.URL.Query().Get("source")
	q.SourceType = r.URL.Query().Get("source_type")
	q.Host = r.URL.Query().Get("host")
	q.Service = r.URL.Query().Get("service")
	q.Severity = r.URL.Query().Get("severity")
	q.EventType = r.URL.Query().Get("event_type")
	q.Category = r.URL.Query().Get("category")
	q.Action = r.URL.Query().Get("action")
	q.Outcome = r.URL.Query().Get("outcome")
	q.User = r.URL.Query().Get("user")
	q.SourceIP = r.URL.Query().Get("source_ip")
	q.DestinationIP = r.URL.Query().Get("destination_ip")
	q.SortBy = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sort_by")))
	q.SortOrder = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sort_order")))
	if q.SortOrder != "" && q.SortOrder != "asc" && q.SortOrder != "desc" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("sort_order must be asc or desc"))
		return
	}
	if q.Attributes == nil {
		q.Attributes = make(map[string]string)
	}
	for key, values := range r.URL.Query() {
		if !strings.HasPrefix(key, "attr.") || len(values) == 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(key[len("attr."):]))
		if name == "" {
			api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("attribute name is required"))
			return
		}
		if !validAttrKeyRe.MatchString(name) {
			api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("attribute name contains invalid characters"))
			return
		}
		q.Attributes[name] = values[len(values)-1]
	}

	if startTime := r.URL.Query().Get("start"); startTime != "" {
		q.Start = parseQueryParamTime(startTime)
	}
	if endTime := r.URL.Query().Get("end"); endTime != "" {
		q.End = parseQueryParamTime(endTime)
	}

	for _, attr := range r.URL.Query()["attr"] {
		parts := strings.SplitN(attr, "=", 2)
		if len(parts) == 2 {
			if q.Attributes == nil {
				q.Attributes = make(map[string]string)
			}
			q.Attributes[parts[0]] = parts[1]
		}
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			if l > maxAPIPageLimit {
				l = maxAPIPageLimit
			}
			q.Limit = l
		} else {
			q.Limit = 100
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o > 0 {
			if o > maxAPIPageOffset {
				o = maxAPIPageOffset
			}
			q.Offset = o
		}
	}

	total, err := h.store.Count(r.Context(), q)
	if err != nil {
		if errors.Is(err, events.ErrInvalidQuery) {
			api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(err.Error()))
			return
		}
		h.logger.Error("list events count", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to count events"))
		return
	}

	evs, err := h.store.Search(r.Context(), q)
	if err != nil {
		if errors.Is(err, events.ErrInvalidQuery) {
			api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(err.Error()))
			return
		}
		h.logger.Error("list events", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list events"))
		return
	}

	pagination := map[string]any{
		"total":    total,
		"limit":    q.Limit,
		"offset":   q.Offset,
		"has_more": (q.Offset + q.Limit) < total,
	}

	result := map[string]any{
		"events":     evs,
		"pagination": pagination,
	}

	api.WriteJSON(w, http.StatusOK, api.Success(result))
}

// ─────────────────────────────────────────────
// Search
// ─────────────────────────────────────────────

// SearchRequest holds the body of a search query request.
type SearchRequest struct {
	Query  string `json:"query"`
	Limit  int    `json:"limit"`
	Offset int    `json:"offset"`
}

// Search executes a search query using the query engine.
func (h *Handler) Search(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid search request body"))
		return
	}

	if req.Query == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("query is required"))
		return
	}

	if req.Limit <= 0 {
		req.Limit = 100
	}
	if req.Limit > maxAPIPageLimit {
		req.Limit = maxAPIPageLimit
	}
	if req.Offset < 0 {
		req.Offset = 0
	}
	if req.Offset > maxAPIPageOffset {
		req.Offset = maxAPIPageOffset
	}

	searchReq := query.SearchRequest{
		Query:  req.Query,
		Limit:  req.Limit,
		Offset: req.Offset,
	}

	result, err := h.searchSvc.Execute(ctx, searchReq)
	if err != nil {
		h.logger.Error("search", "query", req.Query, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("search failed"))
		return
	}

	resp := map[string]any{
		"columns": result.Columns,
		"results": result.Results,
		"count":   result.Count,
		"query":   req.Query,
	}

	api.WriteJSON(w, http.StatusOK, api.Success(resp))
}

// ─────────────────────────────────────────────
// Alert Handlers
// ─────────────────────────────────────────────

// ListAlerts returns a list of alerts.
func (h *Handler) ListAlerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	filter := alerts.Filter{}
	if severity := r.URL.Query().Get("severity"); severity != "" {
		filter.Severity = severity
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = status
	}
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			filter.Limit = l
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			filter.Offset = o
		}
	}

	aks, err := h.alertStore.List(ctx, filter)
	if err != nil {
		h.logger.Error("list alerts", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list alerts"))
		return
	}

	api.WriteJSON(w, http.StatusOK, api.Success(aks))
}

// GetAlert retrieves an alert by its ID.
func (h *Handler) GetAlert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("missing alert ID"))
		return
	}

	a, err := h.alertStore.GetByID(ctx, id)
	if err != nil {
		api.WriteJSON(w, http.StatusNotFound, api.NotFound(fmt.Sprintf("alert %s not found", id)))
		return
	}

	api.WriteJSON(w, http.StatusOK, api.Success(a))
}

// AcknowledgeAlert marks an alert as acknowledged.
func (h *Handler) AcknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("missing alert ID"))
		return
	}

	if err := h.alertStore.UpdateStatus(ctx, id, "acknowledged"); err != nil {
		h.logger.Error("acknowledge alert", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to acknowledge alert"))
		return
	}

	h.logger.Info("alert acknowledged", "id", id)
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"acknowledged": true}))
}

// ResolveAlert marks an alert as resolved.
func (h *Handler) ResolveAlert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("missing alert ID"))
		return
	}

	if err := h.alertStore.UpdateStatus(ctx, id, "resolved"); err != nil {
		h.logger.Error("resolve alert", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to resolve alert"))
		return
	}

	h.logger.Info("alert resolved", "id", id)
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"resolved": true}))
}

// AddNotesToAlert adds notes to an alert.
func (h *Handler) AddNotesToAlert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("missing alert ID"))
		return
	}

	var req struct {
		Content string `json:"content"`
		Author  string `json:"author"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid request body"))
		return
	}

	if req.Content == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("content is required"))
		return
	}

	if req.Author == "" {
		req.Author = "anonymous"
	}

	note := &alerts.Note{
		AlertID:   id,
		Author:    req.Author,
		Content:   req.Content,
		CreatedAt: time.Now(),
	}

	if err := h.alertStore.AddNote(ctx, note); err != nil {
		h.logger.Error("add notes to alert", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to add notes"))
		return
	}

	h.logger.Info("notes added to alert", "id", id)
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"notes_added": 1}))
}

// ─────────────────────────────────────────────
// Incident Handlers
// ─────────────────────────────────────────────

// ListIncidents returns a list of incidents.
func (h *Handler) ListIncidents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	filter := incidents.Filter{}
	if severity := r.URL.Query().Get("severity"); severity != "" {
		filter.Severity = severity
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = status
	}
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			filter.Limit = l
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			filter.Offset = o
		}
	}

	incs, err := h.incidentStore.List(ctx, filter)
	if err != nil {
		h.logger.Error("list incidents", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list incidents"))
		return
	}

	api.WriteJSON(w, http.StatusOK, api.Success(incs))
}

// CreateIncident creates a new incident.
func (h *Handler) CreateIncident(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var inc incidents.Incident
	if err := json.NewDecoder(r.Body).Decode(&inc); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid incident body"))
		return
	}

	if inc.Title == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("title is required"))
		return
	}

	if err := h.incidentStore.Create(ctx, &inc); err != nil {
		h.logger.Error("create incident", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to create incident"))
		return
	}

	h.logger.Info("incident created", "id", inc.ID, "title", inc.Title)
	api.WriteJSON(w, http.StatusCreated, api.Success(&inc))
}

// GetIncident retrieves an incident by its ID.
func (h *Handler) GetIncident(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("missing incident ID"))
		return
	}

	inc, err := h.incidentStore.GetByID(ctx, id)
	if err != nil {
		api.WriteJSON(w, http.StatusNotFound, api.NotFound(fmt.Sprintf("incident %s not found", id)))
		return
	}

	api.WriteJSON(w, http.StatusOK, api.Success(inc))
}

// AcknowledgeIncident marks an incident as acknowledged.
func (h *Handler) AcknowledgeIncident(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("missing incident ID"))
		return
	}

	if err := h.incidentStore.UpdateStatus(ctx, id, "investigating"); err != nil {
		h.logger.Error("acknowledge incident", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to acknowledge incident"))
		return
	}

	h.logger.Info("incident acknowledged", "id", id)
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"acknowledged": true}))
}

// ResolveIncident marks an incident as resolved.
func (h *Handler) ResolveIncident(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("missing incident ID"))
		return
	}

	if err := h.incidentStore.UpdateStatus(ctx, id, "resolved"); err != nil {
		h.logger.Error("resolve incident", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to resolve incident"))
		return
	}

	h.logger.Info("incident resolved", "id", id)
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"resolved": true}))
}

// ─────────────────────────────────────────────
// Detection Handlers
// ─────────────────────────────────────────────

// ListDetections returns a list of detection rules.
func (h *Handler) ListDetections(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rules, err := h.detectionStore.List(ctx)
	if err != nil {
		h.logger.Error("list detections", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list detections"))
		return
	}

	api.WriteJSON(w, http.StatusOK, api.Success(rules))
}

// CreateDetection creates a new detection rule.
func (h *Handler) CreateDetection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var rule detections.DetectionRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid detection body"))
		return
	}

	if rule.Name == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("name is required"))
		return
	}

	if rule.Query == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("query is required"))
		return
	}

	if err := h.detectionStore.Create(ctx, &rule); err != nil {
		h.logger.Error("create detection", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to create detection rule"))
		return
	}

	h.logger.Info("detection created", "id", rule.ID, "name", rule.Name)
	api.WriteJSON(w, http.StatusCreated, api.Success(&rule))
}

// UpdateDetection updates an existing detection rule.
func (h *Handler) UpdateDetection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("missing detection ID"))
		return
	}

	var rule detections.DetectionRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid detection body"))
		return
	}

	rule.ID = id

	if err := h.detectionStore.Update(ctx, &rule); err != nil {
		h.logger.Error("update detection", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to update detection rule"))
		return
	}

	h.logger.Info("detection updated", "id", id)
	api.WriteJSON(w, http.StatusOK, api.Success(&rule))
}

// DeleteDetection removes a detection rule.
func (h *Handler) DeleteDetection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("missing detection ID"))
		return
	}

	if err := h.detectionStore.Delete(ctx, id); err != nil {
		h.logger.Error("delete detection", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to delete detection rule"))
		return
	}

	h.logger.Info("detection deleted", "id", id)
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"deleted": true}))
}

// ExecuteDetection manually executes a detection rule.
func (h *Handler) ExecuteDetection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("missing detection ID"))
		return
	}

	rule, err := h.detectionStore.GetByID(ctx, id)
	if err != nil {
		h.logger.Error("get detection for execution", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to get detection rule"))
		return
	}

	result, err := h.detectionStore.ExecuteNow(ctx, rule, h.store)
	if err != nil {
		h.logger.Error("execute detection", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to execute detection rule"))
		return
	}

	api.WriteJSON(w, http.StatusOK, api.Success(result))
}

// parseQueryParamTime attempts to parse a time string from a query parameter.
func parseQueryParamTime(s string) time.Time {
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, layout := range formats {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// startTime is the time at which the first handler was constructed.
var startTime = time.Now()

// ─────────────────────────────────────────────
// Authentication & User Management Handlers
// ─────────────────────────────────────────────

// LoginRequest holds the body of a login request.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// PasswordChangeRequest holds the body of a password change request.
type PasswordChangeRequest struct {
	CurrentPassword string `json:"current_password,omitempty"`
	NewPassword     string `json:"new_password"`
}

// CreateUserRequest holds the body of a create user request.
type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// Login handles user authentication and returns a token.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid request body"))
		return
	}

	if req.Username == "" || req.Password == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("username and password are required"))
		return
	}

	user, err := h.authStore.Authenticate(ctx, req.Username, req.Password)
	if err != nil {
		h.logger.Warn("login failed", "username", req.Username, "error", err)
		api.WriteJSON(w, http.StatusUnauthorized, api.Unauthorized("invalid credentials"))
		return
	}

	token, err := h.authStore.CreateAPIToken(ctx, user.ID, "login")
	if err != nil {
		h.logger.Error("create token", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to create token"))
		return
	}

	h.authStore.LogAudit(ctx, user.ID, "login", "auth", fmt.Sprintf("User %s logged in", req.Username), r.RemoteAddr)

	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"token": token,
		"user": map[string]any{
			"id":       user.ID,
			"username": user.Username,
			"role":     user.Role,
			"enabled":  user.Enabled,
		},
	}))
}

// GetMe returns the currently authenticated user info (no sensitive fields).
func (h *Handler) GetMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	user, err := currentUser(ctx, h.authStore)
	if err != nil {
		api.WriteJSON(w, http.StatusUnauthorized, api.Unauthorized("not authenticated"))
		return
	}

	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"id":       user.ID,
		"username": user.Username,
		"role":     user.Role,
		"enabled":  user.Enabled,
	}))
}

// UpdateMyPassword allows a user to change their own password.
func (h *Handler) UpdateMyPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	user, err := currentUser(ctx, h.authStore)
	if err != nil {
		api.WriteJSON(w, http.StatusUnauthorized, api.Unauthorized("not authenticated"))
		return
	}

	var req PasswordChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid request body"))
		return
	}

	if req.CurrentPassword == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("current password is required"))
		return
	}

	if req.NewPassword == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("new password is required"))
		return
	}

	if !h.authStore.CheckPassword(user.PasswordHash, req.CurrentPassword) {
		h.authStore.LogAudit(ctx, user.ID, "password_change", "user", "Failed password change attempt", r.RemoteAddr)
		api.WriteJSON(w, http.StatusUnauthorized, api.Unauthorized("current password is incorrect"))
		return
	}

	if err := h.authStore.UpdatePassword(ctx, user.ID, req.NewPassword); err != nil {
		h.logger.Error("update password", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to update password"))
		return
	}

	h.authStore.LogAudit(ctx, user.ID, "password_change", "user", "Password changed successfully", r.RemoteAddr)

	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"updated": true}))
}

// ListUsers returns a list of all users (admin only). Password hashes are not included.
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	admin, err := currentUser(ctx, h.authStore)
	if err != nil {
		api.WriteJSON(w, http.StatusUnauthorized, api.Unauthorized("not authenticated"))
		return
	}
	if !isAdmin(admin.Role) {
		api.WriteJSON(w, http.StatusForbidden, api.Forbidden("admin access required"))
		return
	}

	users, err := h.authStore.ListUsers(ctx)
	if err != nil {
		h.logger.Error("list users", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list users"))
		return
	}

	h.authStore.LogAudit(ctx, admin.ID, "list_users", "users", "Admin listed all users", r.RemoteAddr)

	api.WriteJSON(w, http.StatusOK, api.Success(users))
}

// CreateUser creates a new user (admin only). Passwords are hashed with bcrypt.
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	admin, err := currentUser(ctx, h.authStore)
	if err != nil {
		api.WriteJSON(w, http.StatusUnauthorized, api.Unauthorized("not authenticated"))
		return
	}
	if !isAdmin(admin.Role) {
		api.WriteJSON(w, http.StatusForbidden, api.Forbidden("admin access required"))
		return
	}

	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid request body"))
		return
	}

	if req.Username == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("username is required"))
		return
	}

	if req.Password == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("password is required"))
		return
	}

	if req.Role == "" {
		req.Role = auth.RoleViewer
	}

	if err := h.authStore.CreateUser(ctx, req.Username, req.Password, req.Role); err != nil {
		h.logger.Error("create user", "error", err)
		if err == auth.ErrUserExists {
			api.WriteJSON(w, http.StatusConflict, api.Conflict("username already exists"))
			return
		}
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to create user"))
		return
	}

	h.authStore.LogAudit(ctx, admin.ID, "create_user", "users", fmt.Sprintf("Admin created user %s with role %s", req.Username, req.Role), r.RemoteAddr)

	api.WriteJSON(w, http.StatusCreated, api.Success(map[string]any{
		"username": req.Username,
		"role":     req.Role,
	}))
}

// UpdateUser updates an existing user (admin only).
func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	admin, err := currentUser(ctx, h.authStore)
	if err != nil {
		api.WriteJSON(w, http.StatusUnauthorized, api.Unauthorized("not authenticated"))
		return
	}
	if !isAdmin(admin.Role) {
		api.WriteJSON(w, http.StatusForbidden, api.Forbidden("admin access required"))
		return
	}

	id := r.PathValue("id")
	if id == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("missing user ID"))
		return
	}

	_, err = h.authStore.GetUser(ctx, id)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			api.WriteJSON(w, http.StatusNotFound, api.NotFound(fmt.Sprintf("user %s not found", id)))
			return
		}
		h.logger.Error("get user", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to retrieve user"))
		return
	}

	var req struct {
		Username *string `json:"username,omitempty"`
		Password *string `json:"password,omitempty"`
		Role     *string `json:"role,omitempty"`
		Enabled  *bool   `json:"enabled,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid request body"))
		return
	}

	var username, role string
	if req.Username != nil {
		username = *req.Username
	}
	if req.Role != nil {
		role = *req.Role
	}

	if err := h.authStore.UpdateUser(ctx, id, username, role, req.Enabled); err != nil {
		h.logger.Error("update user", "id", id, "error", err)
		if errors.Is(err, auth.ErrInvalidRole) {
			api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(err.Error()))
			return
		}
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to update user"))
		return
	}
	if req.Password != nil {
		if err := h.authStore.UpdatePassword(ctx, id, *req.Password); err != nil {
			h.logger.Error("update user password", "id", id, "error", err)
			if errors.Is(err, auth.ErrPasswordTooShort) {
				api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(err.Error()))
				return
			}
			api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to update password"))
			return
		}
	}

	h.authStore.LogAudit(ctx, admin.ID, "update_user", "users", fmt.Sprintf("Admin updated user %s", id), r.RemoteAddr)

	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"updated": true}))
}

// DeleteUser removes a user (admin only).
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	admin, err := currentUser(ctx, h.authStore)
	if err != nil {
		api.WriteJSON(w, http.StatusUnauthorized, api.Unauthorized("not authenticated"))
		return
	}
	if !isAdmin(admin.Role) {
		api.WriteJSON(w, http.StatusForbidden, api.Forbidden("admin access required"))
		return
	}

	id := r.PathValue("id")
	if id == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("missing user ID"))
		return
	}

	if err := h.authStore.DeleteUser(ctx, id); err != nil {
		if err == auth.ErrUserIsAdmin {
			api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("cannot disable the last admin user"))
			return
		}
		h.logger.Error("delete user", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to delete user"))
		return
	}

	h.authStore.LogAudit(ctx, admin.ID, "delete_user", "users", fmt.Sprintf("Admin deleted user %s", id), r.RemoteAddr)

	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"deleted": true}))
}

// UpdateUserPassword allows an admin to reset another user's password.
func (h *Handler) UpdateUserPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	admin, err := currentUser(ctx, h.authStore)
	if err != nil {
		api.WriteJSON(w, http.StatusUnauthorized, api.Unauthorized("not authenticated"))
		return
	}
	if !isAdmin(admin.Role) {
		api.WriteJSON(w, http.StatusForbidden, api.Forbidden("admin access required"))
		return
	}

	id := r.PathValue("id")
	if id == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("missing user ID"))
		return
	}

	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid request body"))
		return
	}

	if req.NewPassword == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("new password is required"))
		return
	}

	if err := h.authStore.UpdatePassword(ctx, id, req.NewPassword); err != nil {
		h.logger.Error("update user password", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to update password"))
		return
	}

	h.authStore.LogAudit(ctx, admin.ID, "reset_password", "users", fmt.Sprintf("Admin reset password for user %s", id), r.RemoteAddr)

	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"updated": true}))
}

// Logout revokes the current token.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	user, err := currentUser(ctx, h.authStore)
	if err != nil {
		api.WriteJSON(w, http.StatusUnauthorized, api.Unauthorized("not authenticated"))
		return
	}

	authHeader := r.Header.Get("Authorization")
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		api.WriteJSON(w, http.StatusUnauthorized, api.Unauthorized("missing bearer token"))
		return
	}
	if err := h.authStore.RevokeAPITokenByValue(ctx, parts[1]); err != nil {
		h.logger.Error("logout token revocation", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to revoke token"))
		return
	}

	h.authStore.LogAudit(ctx, user.ID, "logout", "auth", "User logged out", r.RemoteAddr)

	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"logged_out": true}))
}

// currentUser retrieves the current user from the auth context.
func currentUser(ctx context.Context, store *auth.Store) (*auth.User, error) {
	authHeader := ctx.Value(auth.AuthCtxKey{})
	if authHeader == nil {
		return nil, fmt.Errorf("no auth header in context")
	}
	parts := strings.SplitN(authHeader.(string), " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return nil, fmt.Errorf("invalid auth header")
	}

	token, err := store.ValidateAPIToken(ctx, parts[1])
	if err != nil {
		return nil, err
	}

	user, err := store.GetUser(ctx, token.UserID)
	if err != nil {
		return nil, err
	}
	// Disabled/soft-deleted accounts lose access immediately, even with a
	// previously issued token.
	if !user.Enabled {
		return nil, fmt.Errorf("account disabled")
	}
	return user, nil
}

// isAdmin returns true if the role is admin.
func isAdmin(role string) bool {
	return role == auth.RoleAdmin
}
