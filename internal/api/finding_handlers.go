package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"quetzalog/internal/events"
	"quetzalog/internal/findings"
	"quetzalog/internal/risk"
	"quetzalog/pkg/api"
	"quetzalog/pkg/event"
)

// parseFindingFilter maps the analyst queue query parameters to a findings.Filter.
func parseFindingFilter(r *http.Request) (findings.Filter, error) {
	q := r.URL.Query()
	f := findings.Filter{}
	f.Severity = strings.ToLower(q.Get("severity"))
	f.Status = q.Get("status")
	f.Owner = q.Get("owner")
	f.DetectionID = q.Get("detection_id")
	f.User = q.Get("user")
	f.Host = q.Get("host")
	f.SourceIP = q.Get("source_ip")
	f.DestIP = q.Get("destination_ip")
	f.Tactic = q.Get("tactic")
	f.Technique = q.Get("technique")
	f.Source = q.Get("source")
	f.Tag = q.Get("tag")
	f.Text = q.Get("q")
	f.SortBy = q.Get("sort_by")
	f.SortOrder = q.Get("sort_order")

	if s := q.Get("start"); s != "" {
		f.Start = parseQueryParamTime(s)
	}
	if e := q.Get("end"); e != "" {
		f.End = parseQueryParamTime(e)
	}
	if rm := q.Get("risk_min"); rm != "" {
		v, err := strconv.ParseFloat(rm, 64)
		if err != nil {
			return f, fmt.Errorf("risk_min must be a number")
		}
		f.RiskMin = v
	}
	if q.Get("has_risk") == "true" {
		f.HasRisk = true
	}
	if l := q.Get("limit"); l != "" {
		v, err := strconv.Atoi(l)
		if err != nil || v <= 0 {
			return f, fmt.Errorf("limit must be a positive integer")
		}
		f.Limit = v
	}
	if o := q.Get("offset"); o != "" {
		v, err := strconv.Atoi(o)
		if err != nil || v < 0 {
			return f, fmt.Errorf("offset must be a non-negative integer")
		}
		f.Offset = v
	}
	return f, nil
}

// ListFindings returns the filtered analyst queue with total count.
func (h *Handler) ListFindings(w http.ResponseWriter, r *http.Request) {
	filter, err := parseFindingFilter(r)
	if err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(err.Error()))
		return
	}

	list, total, err := h.findingStore.List(r.Context(), filter)
	if err != nil {
		h.logger.Error("list findings", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list findings"))
		return
	}

	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"findings": list,
		"total":    total,
		"pagination": map[string]any{
			"limit":    filter.Limit,
			"offset":   filter.Offset,
			"has_more": filter.Offset+filter.Limit < total,
		},
	}))
}

// GetFinding returns a single finding with notes.
func (h *Handler) GetFinding(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	f, err := h.findingStore.GetByID(r.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			api.WriteJSON(w, http.StatusNotFound, api.NotFound(fmt.Sprintf("finding %s not found", id)))
			return
		}
		h.logger.Error("get finding", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to get finding"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(f))
}

// UpdateFindingRequest carries the mutable fields of a finding.
type UpdateFindingRequest struct {
	Title       *string  `json:"title,omitempty"`
	Description *string  `json:"description,omitempty"`
	Severity    *string  `json:"severity,omitempty"`
	Status      *string  `json:"status,omitempty"`
	Owner       *string  `json:"owner,omitempty"`
	RiskScore   *float64 `json:"risk_score,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// UpdateFinding patches finding fields; status changes are audited.
func (h *Handler) UpdateFinding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	var req UpdateFindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid request body"))
		return
	}

	f, err := h.findingStore.GetByID(ctx, id)
	if err != nil {
		api.WriteJSON(w, http.StatusNotFound, api.NotFound(fmt.Sprintf("finding %s not found", id)))
		return
	}

	if req.Status != nil && !findings.ValidStatus(*req.Status) {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(
			fmt.Sprintf("invalid status %q, expected one of: %s", *req.Status, strings.Join(findings.Statuses, ", "))))
		return
	}
	if req.Severity != nil && *req.Severity != "" {
		sev := findings.Severity(*req.Severity)
		if sev == "" {
			api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid severity"))
			return
		}
	}

	oldStatus, oldOwner, oldRisk := f.Status, f.Owner, f.RiskScore
	if req.Title != nil && strings.TrimSpace(*req.Title) != "" {
		f.Title = *req.Title
	}
	if req.Description != nil {
		f.Description = *req.Description
	}
	if req.Severity != nil && *req.Severity != "" {
		f.Severity = findings.Severity(*req.Severity)
	}
	if req.Status != nil {
		f.Status = *req.Status
	}
	if req.Owner != nil {
		f.Owner = *req.Owner
	}
	if req.RiskScore != nil && *req.RiskScore >= 0 {
		f.RiskScore = *req.RiskScore
	}
	if req.Tags != nil {
		f.Tags = req.Tags
	}

	if err := h.findingStore.Update(ctx, f); err != nil {
		h.logger.Error("update finding", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to update finding"))
		return
	}

	actor := h.auditActor(r)
	if f.Status != oldStatus {
		h.logAudit(actor, "finding.status_change", "finding:"+id,
			fmt.Sprintf("Finding %q status %s -> %s", f.Title, oldStatus, f.Status))
	}
	if f.Owner != oldOwner {
		h.logAudit(actor, "finding.assign", "finding:"+id,
			fmt.Sprintf("Finding %q assigned to %s", f.Title, f.Owner))
	}
	if f.RiskScore != oldRisk {
		h.logAudit(actor, "finding.risk_change", "finding:"+id,
			fmt.Sprintf("Finding %q risk %v -> %v", f.Title, oldRisk, f.RiskScore))
	}

	h.logger.Info("finding updated", "id", id, "status", f.Status, "owner", f.Owner)
	api.WriteJSON(w, http.StatusOK, api.Success(f))
}

// AddFindingNoteRequest carries a new finding note.
type AddFindingNoteRequest struct {
	Content string `json:"content"`
}

// AddFindingNote appends a note to a finding.
func (h *Handler) AddFindingNote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	if _, err := h.findingStore.GetByID(ctx, id); err != nil {
		api.WriteJSON(w, http.StatusNotFound, api.NotFound(fmt.Sprintf("finding %s not found", id)))
		return
	}

	var req AddFindingNoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid request body"))
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("content is required"))
		return
	}
	if len(req.Content) > maxCommentBytes {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(fmt.Sprintf("note too long (max %d bytes)", maxCommentBytes)))
		return
	}

	note := &findings.Note{FindingID: id, Author: h.actorUsername(r), Content: req.Content}
	if err := h.findingStore.AddNote(ctx, note); err != nil {
		h.logger.Error("add finding note", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to add note"))
		return
	}
	api.WriteJSON(w, http.StatusCreated, api.Success(note))
}

// FindingEvents returns the events linked to a finding plus correlated
// activity (same user/host/IPs) within the finding's time window.
func (h *Handler) FindingEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	f, err := h.findingStore.GetByID(ctx, id)
	if err != nil {
		api.WriteJSON(w, http.StatusNotFound, api.NotFound(fmt.Sprintf("finding %s not found", id)))
		return
	}

	limit := 200
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 500 {
			limit = v
		}
	}

	windowStart, windowEnd := f.FirstSeen.Add(-time.Hour), f.LastSeen.Add(time.Hour)

	byID := make(map[string]*event.Event, limit)
	add := func(ev *event.Event) {
		if ev == nil || ev.ID == "" {
			return
		}
		if _, ok := byID[ev.ID]; !ok && len(byID) < limit {
			byID[ev.ID] = ev
		}
	}

	for _, evID := range f.EventIDs {
		ev, err := h.store.GetByID(ctx, evID)
		if err == nil {
			add(ev)
		}
	}

	entityFilters := [][4]string{
		{f.User, "", "", ""},
		{"", f.Host, "", ""},
		{"", "", f.SourceIP, ""},
		{"", "", "", f.DestinationIP},
	}
	for _, e := range entityFilters {
		q := events.NewQuery()
		q.User, q.Host, q.SourceIP, q.DestinationIP = e[0], e[1], e[2], e[3]
		if q.User == "" && q.Host == "" && q.SourceIP == "" && q.DestinationIP == "" {
			continue
		}
		q.Start, q.End = windowStart, windowEnd
		q.Limit = 100
		evs, err := h.store.Search(ctx, q)
		if err != nil {
			continue
		}
		for _, ev := range evs {
			add(ev)
		}
	}

	out := make([]*event.Event, 0, len(byID))
	for _, ev := range byID {
		out = append(out, ev)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp.Before(out[j].Timestamp) })

	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"events": out,
		"total":  len(out),
		"window": map[string]string{
			"start": windowStart.UTC().Format(time.RFC3339),
			"end":   windowEnd.UTC().Format(time.RFC3339),
		},
	}))
}

// FindingRisk returns the risk breakdown for a finding's entities.
func (h *Handler) FindingRisk(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	f, err := h.findingStore.GetByID(ctx, id)
	if err != nil {
		api.WriteJSON(w, http.StatusNotFound, api.NotFound(fmt.Sprintf("finding %s not found", id)))
		return
	}

	out := map[string]any{
		"finding_id": f.ID,
		"risk_score": f.RiskScore,
		"entities":   []map[string]any{},
	}

	primary := [][2]string{
		{"user", f.User},
		{"host", f.Host},
		{"ip", f.SourceIP},
		{"ip", f.DestinationIP},
	}
	for _, p := range primary {
		if p[1] == "" {
			continue
		}
		er := map[string]any{"type": p[0], "value": p[1], "risk_score": 0.0, "contributions": []risk.Contribution{}}
		if h.riskStore != nil {
			if erisk, err := h.riskStore.Get(ctx, p[0], p[1]); err == nil && erisk != nil {
				er["risk_score"] = erisk.RiskScore
				er["updated_at"] = erisk.Updated
			}
			contribs, _ := h.riskStore.Contributions(ctx, p[0], p[1], 20)
			if contribs != nil {
				er["contributions"] = contribs
			}
		}
		out["entities"] = append(out["entities"].([]map[string]any), er)
	}

	api.WriteJSON(w, http.StatusOK, api.Success(out))
}

// ── saved views ─────────────────────────────────────────────

// ListSavedViews returns the current user's saved queue views.
func (h *Handler) ListSavedViews(w http.ResponseWriter, r *http.Request) {
	user := h.actorUsername(r)
	if user == "" {
		user = "anonymous"
	}
	views, err := h.findingStore.ListViews(r.Context(), user)
	if err != nil {
		h.logger.Error("list saved views", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list saved views"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(views))
}

// SaveSavedViewRequest carries a new saved view.
type SaveSavedViewRequest struct {
	Name    string            `json:"name"`
	Filters map[string]string `json:"filters"`
}

// SaveSavedView stores a named queue filter set for the current user.
func (h *Handler) SaveSavedView(w http.ResponseWriter, r *http.Request) {
	var req SaveSavedViewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid request body"))
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("name is required"))
		return
	}
	if req.Filters == nil {
		req.Filters = map[string]string{}
	}

	user := h.actorUsername(r)
	if user == "" {
		user = "anonymous"
	}

	view := &findings.SavedView{User: user, Name: req.Name, Filters: req.Filters}
	if err := h.findingStore.SaveView(r.Context(), view); err != nil {
		h.logger.Error("save view", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to save view"))
		return
	}
	api.WriteJSON(w, http.StatusCreated, api.Success(view))
}

// DeleteSavedView removes a saved view owned by the current user.
func (h *Handler) DeleteSavedView(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	user := h.actorUsername(r)
	if user == "" {
		user = "anonymous"
	}
	if err := h.findingStore.DeleteView(r.Context(), user, id); err != nil {
		h.logger.Error("delete view", "id", id, "error", err)
		api.WriteJSON(w, http.StatusNotFound, api.NotFound("saved view not found"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"deleted": true}))
}


