package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"quetzalog/internal/ai"
	"quetzalog/pkg/api"
)

// ─────────────────────────────────────────────
// AI Analyst (investigation)
// ─────────────────────────────────────────────

// ListAIAnalyst returns the list of AI analyses (newest first).
// GET /api/v1/ai-analyst?status=&severity=&limit=&offset=
func (h *Handler) ListAIAnalyst(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	f := ai.ListFilter{
		Status:   r.URL.Query().Get("status"),
		Severity: r.URL.Query().Get("severity"),
		Offset:   0,
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		f.Limit, _ = strconv.Atoi(v)
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		f.Offset, _ = strconv.Atoi(v)
	}
	rows, total, err := h.aiStore.List(ctx, f)
	if err != nil {
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list ai analyses"))
		return
	}
	if rows == nil {
		rows = []*ai.Row{}
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"analyses": rows,
		"total":    total,
		"pagination": map[string]any{
			"limit":    f.Limit,
			"offset":   f.Offset,
			"has_more": f.Offset+f.Limit < total,
		},
	}))
}

// GetAIAnalyst returns one analysis with its analysis payload and context.
// GET /api/v1/ai-analyst/{id}
func (h *Handler) GetAIAnalyst(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	row, a, c, err := h.aiStore.Get(ctx, id)
	if err != nil {
		writeAIErr(w, err)
		return
	}
	finding, _ := h.findingStore.GetByID(ctx, row.FindingID)
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"analysis":  row,
		"ai":        a,
		"context":   c,
		"finding":   finding,
	}))
}

// GetAIAnalystByFinding returns the analysis attached to a finding (if any).
// GET /api/v1/ai-analyst/finding/{findingID}
func (h *Handler) GetAIAnalystByFinding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	findingID := r.PathValue("findingID")
	row, err := h.aiStore.ActiveByFinding(ctx, findingID)
	if err != nil {
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to load ai analysis"))
		return
	}
	if row == nil {
		api.WriteJSON(w, http.StatusNotFound, api.NotFound("no ai analysis for this finding"))
		return
	}
	a, c, _ := h.aiStoreFull(ctx, row.ID)
	finding, _ := h.findingStore.GetByID(ctx, findingID)
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"analysis": row,
		"ai":       a,
		"context":  c,
		"finding":  finding,
	}))
}

// AnalyzeAIFinding starts (or restarts) an analysis for a finding in the
// background and returns immediately.
// POST /api/v1/ai-analyst/analyze  body: {"finding_id": "..."}
func (h *Handler) AnalyzeAIFinding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var body struct {
		FindingID string `json:"finding_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.FindingID == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("finding_id is required"))
		return
	}
	row, err := h.aiService.StartAnalysis(ctx, body.FindingID)
	if err != nil {
		if errors.Is(err, ai.ErrInProgress) {
			api.WriteJSON(w, http.StatusAccepted, api.Success(map[string]any{
				"started":  false,
				"reason":   "analysis already in progress",
				"analysis": row,
			}))
			return
		}
		writeAIErr(w, err)
		return
	}
	h.logAudit(h.auditActor(r), "ai_analyst.analyze", "finding:"+body.FindingID, "Started AI analysis")
	api.WriteJSON(w, http.StatusAccepted, api.Success(map[string]any{
		"started":  true,
		"finding":  body.FindingID,
	}))
}

// ApproveAIAnalysis records the human approval.
// POST /api/v1/ai-analyst/{id}/approve
func (h *Handler) ApproveAIAnalysis(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	row, err := h.aiService.Approve(ctx, id, h.actorUsername(r))
	if err != nil {
		writeAIErr(w, err)
		return
	}
	h.logAudit(h.auditActor(r), "ai_analyst.approve", "ai-analyst:"+id, "Approved recommendation: "+row.RecommendationType)
	api.WriteJSON(w, http.StatusOK, api.Success(row))
}

// DismissAIAnalysis records the human dismissal with an optional reason.
// POST /api/v1/ai-analyst/{id}/dismiss  body: {"reason": "..."}
func (h *Handler) DismissAIAnalysis(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	row, err := h.aiService.Dismiss(ctx, id, body.Reason, h.actorUsername(r))
	if err != nil {
		writeAIErr(w, err)
		return
	}
	h.logAudit(h.auditActor(r), "ai_analyst.dismiss", "ai-analyst:"+id, "Dismissed recommendation: "+row.RecommendationType+" — "+body.Reason)
	api.WriteJSON(w, http.StatusOK, api.Success(row))
}

// ─────────────────────────────────────────────
// AI Analyst settings
// ─────────────────────────────────────────────

// aiConfigView is the redacted AI configuration returned to the UI. The API
// key is never returned — only whether one is set.
type aiConfigView struct {
	Enabled              bool   `json:"enabled"`
	Provider             string `json:"provider"`
	Endpoint             string `json:"endpoint"`
	APIKeySet            bool   `json:"api_key_set"`
	Username             string `json:"username"`
	Model                string `json:"model"`
	MinimumSeverity      string `json:"minimum_severity"`
	MaxRequestsPerMinute int    `json:"max_requests_per_minute"`
	TimeoutSeconds       int    `json:"timeout_seconds"`
	MaxContextEvents     int    `json:"max_context_events"`
	RetryCount           int    `json:"retry_count"`
	Persisted            bool   `json:"persisted"`
}

// GetAIConfig returns the current AI configuration with the key redacted.
// GET /api/v1/settings/ai-analyst
func (h *Handler) GetAIConfig(w http.ResponseWriter, r *http.Request) {
	h.writeAIConfig(w, http.StatusOK)
}

// PutAIConfig updates the AI configuration. Admin only.
// PUT /api/v1/settings/ai-analyst
func (h *Handler) PutAIConfig(w http.ResponseWriter, r *http.Request) {
	if h.requireAdmin(w, r) {
		return
	}
	var in ai.AIAnalystView
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid body"))
		return
	}
	if err := h.aiService.UpdateConfig(r.Context(), in.ToConfig(h.aiService.Config())); err != nil {
		writeAIErr(w, err)
		return
	}
	h.logAudit(h.auditActor(r), "ai_analyst.config", "settings", "Updated AI Analyst configuration")
	h.writeAIConfig(w, http.StatusOK)
}

// TestAIConnection probes the configured provider without running an analysis.
// POST /api/v1/settings/ai-analyst/test
func (h *Handler) TestAIConnection(w http.ResponseWriter, r *http.Request) {
	health, err := h.aiService.TestConnection(r.Context())
	if err != nil {
		api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
			"ok":      false,
			"detail":  err.Error(),
		}))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"ok":       health.OK,
		"provider": health.Provider,
		"model":    health.Model,
		"latency":  health.Latency.String(),
		"detail":   health.Detail,
	}))
}

// ListAIModels lists models offered by the configured provider (when
// supported).
// GET /api/v1/settings/ai-analyst/models
func (h *Handler) ListAIModels(w http.ResponseWriter, r *http.Request) {
	ids, ok, err := h.aiService.ListModels(r.Context())
	if err != nil {
		api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"supported": false, "detail": err.Error()}))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"supported": ok, "models": ids}))
}

// writeAIConfig renders the redacted view.
func (h *Handler) writeAIConfig(w http.ResponseWriter, status int) {
	cfg := h.aiService.Config()
	api.WriteJSON(w, status, api.Success(aiConfigView{
		Enabled:              cfg.Enabled,
		Provider:             cfg.Provider,
		Endpoint:             cfg.Endpoint,
		APIKeySet:            cfg.APIKey != "",
		Username:             cfg.Username,
		Model:                cfg.Model,
		MinimumSeverity:      cfg.MinimumSeverity,
		MaxRequestsPerMinute: cfg.MaxRequestsPerMinute,
		TimeoutSeconds:       cfg.TimeoutSeconds,
		MaxContextEvents:     cfg.MaxContextEvents,
		RetryCount:           cfg.RetryCount,
		Persisted:            h.aiService.Persisted(),
	}))
}

// aiStoreFull is a small helper to fetch analysis+context together.
func (h *Handler) aiStoreFull(ctx context.Context, id string) (*ai.Analysis, *ai.FindingContext, *ai.Row) {
	row, a, c, _ := h.aiStore.Get(ctx, id)
	return a, c, row
}

// requireAdmin enforces the admin role (same convention as the user
// management endpoints) and reports whether the handler should stop.
func (h *Handler) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	u, err := currentUser(r.Context(), h.authStore)
	if err != nil {
		api.WriteJSON(w, http.StatusUnauthorized, api.Unauthorized("not authenticated"))
		return true
	}
	if !isAdmin(u.Role) {
		api.WriteJSON(w, http.StatusForbidden, api.Forbidden("admin access required"))
		return true
	}
	return false
}

// writeAIErr maps service errors onto HTTP statuses.
func writeAIErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ai.ErrNoAnalysis):
		api.WriteJSON(w, http.StatusConflict, api.Conflict("no completed analysis to decide"))
	case errors.Is(err, ai.ErrInProgress):
		api.WriteJSON(w, http.StatusAccepted, api.Success(map[string]any{"reason": "analysis in progress"}))
	case errors.Is(err, ai.ErrNoFinding):
		api.WriteJSON(w, http.StatusNotFound, api.NotFound(err.Error()))
	case errors.Is(err, ai.ErrNotFound):
		api.WriteJSON(w, http.StatusNotFound, api.NotFound(err.Error()))
	case errors.Is(err, ai.ErrDisabled):
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("AI analyst is disabled"))
	case errors.Is(err, ai.ErrBelowSeverity):
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(err.Error()))
	case errors.Is(err, ai.ErrInvalidConfig), errors.Is(err, ai.ErrBadConfig):
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(err.Error()))
	default:
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError(err.Error()))
	}
}
