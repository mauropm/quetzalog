package api

import (
	"encoding/json"
	"net/http"

	"quetzalog/internal/logging"
	"quetzalog/pkg/api"
)

// GetLoggingSettings returns the live log verbosity.
// GET /api/v1/settings/logging
func (h *Handler) GetLoggingSettings(w http.ResponseWriter, r *http.Request) {
	level := h.config.Logging.Level
	if h.logCtl != nil {
		level = h.logCtl.Level()
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"level":     level,
		"available": logging.Levels,
		"managed":   h.logCtl != nil,
	}))
}

// PutLoggingSettings changes the log verbosity at runtime. Admin only. The
// new level applies immediately and is persisted to the config file.
// PUT /api/v1/settings/logging
func (h *Handler) PutLoggingSettings(w http.ResponseWriter, r *http.Request) {
	if h.requireAdmin(w, r) {
		return
	}
	var in struct {
		Level string `json:"level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Level == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(`{"level": "events|warn|info|debug"} required`))
		return
	}
	if _, err := logging.ParseLevel(in.Level); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(err.Error()))
		return
	}
	if h.logCtl == nil {
		api.WriteJSON(w, http.StatusServiceUnavailable,
			api.Error(http.StatusServiceUnavailable, "log level is not runtime-managed by this process"))
		return
	}
	level, warn := h.logCtl.SetLevel(in.Level)
	if warn != nil {
		// The level changed; persistence failed — surface it, don't fail the call.
		api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
			"level": level, "detail": warn.Error(), "managed": true,
		}))
		return
	}
	h.logAudit(h.auditActor(r), "logging.level", "settings", "Log level set to "+level)
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"level": level, "available": logging.Levels, "managed": true,
	}))
}
