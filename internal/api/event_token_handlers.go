package api

import (
	"encoding/json"
	"net/http"

	"quetzalog/pkg/api"
)

// Event tokens are shareable, ingest-only API keys: a holder may only POST
// /api/v1/events and /api/v1/events/batch. Only admins manage them (via this
// API or the CLI on the quetzalog machine). The full token value is stored
// encrypted under a machine-local key so an admin can re-copy it later.

// ListEventTokens lists all event tokens, masked (GET /api/v1/event-tokens).
func (h *Handler) ListEventTokens(w http.ResponseWriter, r *http.Request) {
	if h.requireAdmin(w, r) {
		return
	}
	if h.eventTokens == nil {
		api.WriteJSON(w, http.StatusServiceUnavailable, api.ServiceUnavailable("event token store unavailable"))
		return
	}
	tokens, err := h.eventTokens.List(r.Context())
	if err != nil {
		h.logger.Error("list event tokens", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list event tokens"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(tokens))
}

// CreateEventToken creates a named event token (POST /api/v1/event-tokens).
// The full token value is returned exactly here and on explicit reveal.
func (h *Handler) CreateEventToken(w http.ResponseWriter, r *http.Request) {
	if h.requireAdmin(w, r) {
		return
	}
	if h.eventTokens == nil {
		api.WriteJSON(w, http.StatusServiceUnavailable, api.ServiceUnavailable("event token store unavailable"))
		return
	}
	var in struct {
		Name  string `json:"name"`
		Tag   string `json:"tag"`
		Group string `json:"group"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Name == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("name is required"))
		return
	}
	tok, err := h.eventTokens.Create(r.Context(), in.Name, in.Tag, in.Group, h.auditActor(r))
	if err != nil {
		h.logger.Error("create event token", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to create event token"))
		return
	}
	h.logAudit(h.auditActor(r), "event-token.create", "event-token:"+tok.ID,
		"Created event token "+tok.Name+" (tag "+tok.Tag+", group "+tok.Group+")")
	api.WriteJSON(w, http.StatusCreated, api.Success(map[string]any{
		"id":           tok.ID,
		"name":         tok.Name,
		"tag":          tok.Tag,
		"group":        tok.Group,
		"enabled":      true,
		"token_prefix": tok.TokenPrefix,
		"created_at":   tok.CreatedAt,
		"token":        tok.Token,
	}))
}

// RevealEventToken returns the full token value for re-copying
// (GET /api/v1/event-tokens/{id}/reveal). Admin-only, audited.
func (h *Handler) RevealEventToken(w http.ResponseWriter, r *http.Request) {
	if h.requireAdmin(w, r) {
		return
	}
	if h.eventTokens == nil {
		api.WriteJSON(w, http.StatusServiceUnavailable, api.ServiceUnavailable("event token store unavailable"))
		return
	}
	id := r.PathValue("id")
	tok, err := h.eventTokens.Reveal(r.Context(), id)
	if err != nil {
		api.WriteJSON(w, http.StatusNotFound, api.NotFound("event token not found"))
		return
	}
	h.logAudit(h.auditActor(r), "event-token.reveal", "event-token:"+id, "Revealed an event token for re-copying")
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]string{"token": tok}))
}

// UpdateEventToken renames / retags / regroups a token
// (PATCH /api/v1/event-tokens/{id}).
func (h *Handler) UpdateEventToken(w http.ResponseWriter, r *http.Request) {
	if h.requireAdmin(w, r) {
		return
	}
	if h.eventTokens == nil {
		api.WriteJSON(w, http.StatusServiceUnavailable, api.ServiceUnavailable("event token store unavailable"))
		return
	}
	id := r.PathValue("id")
	var in struct {
		Name  string `json:"name"`
		Tag   string `json:"tag"`
		Group string `json:"group"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Name == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("name is required"))
		return
	}
	if err := h.eventTokens.UpdateNameTags(r.Context(), id, in.Name, in.Tag, in.Group); err != nil {
		h.logger.Warn("update event token", "id", id, "error", err)
		api.WriteJSON(w, http.StatusNotFound, api.NotFound("event token not found"))
		return
	}
	h.logAudit(h.auditActor(r), "event-token.update", "event-token:"+id,
		"Renamed event token to "+in.Name+" (tag "+in.Tag+", group "+in.Group+")")
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]bool{"updated": true}))
}

// ExpireEventToken disables a token (POST /api/v1/event-tokens/{id}/expire).
func (h *Handler) ExpireEventToken(w http.ResponseWriter, r *http.Request) {
	if h.requireAdmin(w, r) {
		return
	}
	if h.eventTokens == nil {
		api.WriteJSON(w, http.StatusServiceUnavailable, api.ServiceUnavailable("event token store unavailable"))
		return
	}
	id := r.PathValue("id")
	if err := h.eventTokens.Expire(r.Context(), id); err != nil {
		h.logger.Warn("expire event token", "id", id, "error", err)
		api.WriteJSON(w, http.StatusNotFound, api.NotFound("event token not found"))
		return
	}
	h.logAudit(h.auditActor(r), "event-token.expire", "event-token:"+id, "Expired an event token")
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]bool{"expired": true}))
}

// DeleteEventToken removes a token permanently (DELETE /api/v1/event-tokens/{id}).
func (h *Handler) DeleteEventToken(w http.ResponseWriter, r *http.Request) {
	if h.requireAdmin(w, r) {
		return
	}
	if h.eventTokens == nil {
		api.WriteJSON(w, http.StatusServiceUnavailable, api.ServiceUnavailable("event token store unavailable"))
		return
	}
	id := r.PathValue("id")
	if err := h.eventTokens.Delete(r.Context(), id); err != nil {
		h.logger.Warn("delete event token", "id", id, "error", err)
		api.WriteJSON(w, http.StatusNotFound, api.NotFound("event token not found"))
		return
	}
	h.logAudit(h.auditActor(r), "event-token.delete", "event-token:"+id, "Deleted an event token")
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]bool{"deleted": true}))
}
