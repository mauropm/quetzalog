package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"quetzalog/internal/findings"
	"quetzalog/internal/investigations"
	"quetzalog/pkg/api"
)

// ListInvestigations returns the investigation list with filters.
func (h *Handler) ListInvestigations(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := investigations.Filter{
		Severity: strings.ToLower(q.Get("severity")),
		Status:   q.Get("status"),
		Assignee: q.Get("assignee"),
		Limit:    100,
	}
	if l := q.Get("limit"); l != "" {
		v, err := strconv.Atoi(l)
		if err != nil || v <= 0 {
			api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("limit must be a positive integer"))
			return
		}
		filter.Limit = v
	}
	if o := q.Get("offset"); o != "" {
		v, err := strconv.Atoi(o)
		if err != nil || v < 0 {
			api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("offset must be a non-negative integer"))
			return
		}
		filter.Offset = v
	}

	list, total, err := h.investigationStore.List(r.Context(), filter)
	if err != nil {
		h.logger.Error("list investigations", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list investigations"))
		return
	}

	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"investigations": list,
		"total":          total,
		"pagination": map[string]any{
			"limit":    filter.Limit,
			"offset":   filter.Offset,
			"has_more": filter.Offset+filter.Limit < total,
		},
	}))
}

// CreateInvestigationRequest carries a new investigation.
type CreateInvestigationRequest struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Assignee    string   `json:"assignee"`
	FindingIDs  []string `json:"finding_ids"`
}

// CreateInvestigation creates an investigation and links findings.
func (h *Handler) CreateInvestigation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CreateInvestigationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid request body"))
		return
	}
	if strings.TrimSpace(req.Title) == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("title is required"))
		return
	}
	if len(req.FindingIDs) > 200 {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("too many finding links (max 200)"))
		return
	}

	in := &investigations.Investigation{
		Title:       strings.TrimSpace(req.Title),
		Description: req.Description,
		Severity:    req.Severity,
		Assignee:    req.Assignee,
		FindingIDs:  req.FindingIDs,
	}
	if in.Assignee == "" {
		in.Assignee = h.actorUsername(r)
	}

	if err := h.investigationStore.Create(ctx, in); err != nil {
		h.logger.Error("create investigation", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to create investigation"))
		return
	}

	h.logAudit(h.auditActor(r), "investigation.create", "investigation:"+in.ID,
		fmt.Sprintf("Investigation %q created", in.Title))

	created, err := h.investigationStore.GetByID(ctx, in.ID)
	if err != nil {
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to load investigation"))
		return
	}
	api.WriteJSON(w, http.StatusCreated, api.Success(created))
}

// GetInvestigation returns a single investigation with notes.
func (h *Handler) GetInvestigation(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	in, err := h.investigationStore.GetByID(r.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			api.WriteJSON(w, http.StatusNotFound, api.NotFound(fmt.Sprintf("investigation %s not found", id)))
			return
		}
		h.logger.Error("get investigation", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to get investigation"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(in))
}

// UpdateInvestigationRequest carries mutable investigation fields.
type UpdateInvestigationRequest struct {
	Title        *string                  `json:"title,omitempty"`
	Description  *string                  `json:"description,omitempty"`
	Severity     *string                  `json:"severity,omitempty"`
	Assignee     *string                  `json:"assignee,omitempty"`
	FindingIDs   []string                 `json:"finding_ids,omitempty"`
	AddEntities  []investigations.Entity  `json:"add_entities,omitempty"`
	Queries      []string                 `json:"queries,omitempty"`
	Techniques   []string                 `json:"techniques,omitempty"`
}

// UpdateInvestigation patches investigation fields.
func (h *Handler) UpdateInvestigation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	var req UpdateInvestigationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid request body"))
		return
	}

	in, err := h.investigationStore.GetByID(ctx, id)
	if err != nil {
		api.WriteJSON(w, http.StatusNotFound, api.NotFound(fmt.Sprintf("investigation %s not found", id)))
		return
	}

	if req.Title != nil && strings.TrimSpace(*req.Title) != "" {
		in.Title = *req.Title
	}
	if req.Description != nil {
		in.Description = *req.Description
	}
	if req.Severity != nil {
		in.Severity = *req.Severity
	}
	if req.Assignee != nil {
		in.Assignee = *req.Assignee
	}
	if req.FindingIDs != nil && len(req.FindingIDs) <= 200 {
		in.FindingIDs = req.FindingIDs
	}
	if len(req.AddEntities) > 0 {
		for _, e := range req.AddEntities {
			if e.Value == "" {
				continue
			}
			if !hasEntity(in.Entities, e) {
				in.Entities = append(in.Entities, e)
			}
		}
	}
	if req.Queries != nil {
		in.Queries = req.Queries
	}
	if req.Techniques != nil {
		in.Techniques = req.Techniques
	}

	if err := h.investigationStore.Update(ctx, in); err != nil {
		h.logger.Error("update investigation", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to update investigation"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(in))
}

// hasEntity reports whether the list already contains a matching entity.
func hasEntity(list []investigations.Entity, e investigations.Entity) bool {
	for _, x := range list {
		if x.Type == e.Type && strings.EqualFold(x.Value, e.Value) {
			return true
		}
	}
	return false
}

// SetInvestigationStatusRequest carries a status transition.
type SetInvestigationStatusRequest struct {
	Status string `json:"status"`
}

// SetInvestigationStatus moves the investigation through its lifecycle.
func (h *Handler) SetInvestigationStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	var req SetInvestigationStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid request body"))
		return
	}
	if !investigations.ValidStatus(req.Status) {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(
			fmt.Sprintf("invalid status %q, expected one of: %s", req.Status, strings.Join(investigations.Statuses, ", "))))
		return
	}

	if err := h.investigationStore.UpdateStatus(ctx, id, req.Status); err != nil {
		if strings.Contains(err.Error(), "not found") {
			api.WriteJSON(w, http.StatusNotFound, api.NotFound(fmt.Sprintf("investigation %s not found", id)))
			return
		}
		h.logger.Error("set investigation status", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to update investigation status"))
		return
	}

	in, _ := h.investigationStore.GetByID(ctx, id)
	title := ""
	if in != nil {
		title = in.Title
	}
	h.logAudit(h.auditActor(r), "investigation.status_change", "investigation:"+id,
		fmt.Sprintf("Investigation %q status -> %s", title, req.Status))

	if in != nil {
		api.WriteJSON(w, http.StatusOK, api.Success(in))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]string{"status": req.Status}))
}

// AddInvestigationNoteRequest carries a new timeline note.
type AddInvestigationNoteRequest struct {
	Body string `json:"body"`
}

// AddInvestigationNote appends an authored timeline entry.
func (h *Handler) AddInvestigationNote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	var req AddInvestigationNoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid request body"))
		return
	}

	note := &investigations.Note{InvestigationID: id, Author: h.actorUsername(r), Body: req.Body}
	created, err := h.investigationStore.AddNote(ctx, note)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			api.WriteJSON(w, http.StatusNotFound, api.NotFound(fmt.Sprintf("investigation %s not found", id)))
			return
		}
		if strings.Contains(err.Error(), "note too long") || strings.Contains(err.Error(), "empty note") {
			api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(err.Error()))
			return
		}
		h.logger.Error("add investigation note", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to add note"))
		return
	}
	api.WriteJSON(w, http.StatusCreated, api.Success(created))
}

// ListInvestigationNotes returns the timeline notes.
func (h *Handler) ListInvestigationNotes(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	notes, err := h.investigationStore.ListNotes(r.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			api.WriteJSON(w, http.StatusNotFound, api.NotFound(fmt.Sprintf("investigation %s not found", id)))
			return
		}
		h.logger.Error("list investigation notes", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list notes"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(notes))
}

// AddInvestigationEvidenceRequest carries event IDs to attach.
type AddInvestigationEvidenceRequest struct {
	EventIDs []string `json:"event_ids"`
}

// AddInvestigationEvidence attaches event evidence to the investigation.
func (h *Handler) AddInvestigationEvidence(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	var req AddInvestigationEvidenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid request body"))
		return
	}
	if len(req.EventIDs) == 0 {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("event_ids is required"))
		return
	}
	if len(req.EventIDs) > 500 {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("too many events (max 500)"))
		return
	}

	if err := h.investigationStore.AddEvents(ctx, id, req.EventIDs); err != nil {
		if strings.Contains(err.Error(), "not found") {
			api.WriteJSON(w, http.StatusNotFound, api.NotFound(fmt.Sprintf("investigation %s not found", id)))
			return
		}
		h.logger.Error("add evidence", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to attach events"))
		return
	}
	in, _ := h.investigationStore.GetByID(ctx, id)
	api.WriteJSON(w, http.StatusOK, api.Success(in))
}

// LinkFindingsRequest carries finding IDs to link.
type LinkFindingsRequest struct {
	FindingIDs []string `json:"finding_ids"`
}

// LinkFindingsToInvestigation adds findings to an investigation.
func (h *Handler) LinkFindingsToInvestigation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	var req LinkFindingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid request body"))
		return
	}
	if len(req.FindingIDs) == 0 {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("finding_ids is required"))
		return
	}
	if len(req.FindingIDs) > 200 {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("too many findings (max 200)"))
		return
	}

	if err := h.investigationStore.AddFindings(ctx, id, req.FindingIDs); err != nil {
		if strings.Contains(err.Error(), "not found") {
			api.WriteJSON(w, http.StatusNotFound, api.NotFound(fmt.Sprintf("investigation %s not found", id)))
			return
		}
		h.logger.Error("link findings", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to link findings"))
		return
	}
	in, _ := h.investigationStore.GetByID(ctx, id)
	api.WriteJSON(w, http.StatusOK, api.Success(in))
}

// InvestigationFindings resolves linked finding IDs to full finding objects.
func (h *Handler) InvestigationFindings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	in, err := h.investigationStore.GetByID(ctx, id)
	if err != nil {
		api.WriteJSON(w, http.StatusNotFound, api.NotFound(fmt.Sprintf("investigation %s not found", id)))
		return
	}

	out := make([]*findings.Finding, 0, len(in.FindingIDs))
	for _, fid := range in.FindingIDs {
		f, err := h.findingStore.GetByID(ctx, fid)
		if err == nil {
			out = append(out, f)
		}
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"findings": out,
		"total":    len(out),
	}))
}
