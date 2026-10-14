package api

import (
	"encoding/json"
	"net/http"

	"quetzalog/internal/ingestion/otlp"
	"quetzalog/pkg/api"
)

// GetOTLPSettings returns the OTLP receiver configuration and live state.
// GET /api/v1/settings/otlp
func (h *Handler) GetOTLPSettings(w http.ResponseWriter, r *http.Request) {
	if h.otlpManager == nil {
		api.WriteJSON(w, http.StatusOK, api.Success(otlp.ManagerStatus{
			Enabled:  h.config.OTel.Enabled,
			HTTPPort: h.config.OTel.HttpPort,
			GRPCPort: h.config.OTel.GrpcPort,
			Detail:   "receivers are not managed by this process",
		}))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(h.otlpManager.Status()))
}

// PutOTLPSettings starts or stops the OTLP receivers. Admin only.
// PUT /api/v1/settings/otlp
func (h *Handler) PutOTLPSettings(w http.ResponseWriter, r *http.Request) {
	if h.requireAdmin(w, r) {
		return
	}
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Enabled == nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(`{"enabled": true|false} required`))
		return
	}
	if h.otlpManager == nil {
		api.WriteJSON(w, http.StatusServiceUnavailable,
			api.Error(http.StatusServiceUnavailable, "OTLP receivers are not managed by this process"))
		return
	}
	st, err := h.otlpManager.SetEnabled(*in.Enabled)
	if err != nil {
		// A port conflict or bind failure is an operator-visible condition.
		api.WriteJSON(w, http.StatusConflict, api.Error(http.StatusConflict, err.Error()))
		return
	}
	action := "disabled"
	if *in.Enabled {
		action = "enabled"
	}
	h.logAudit(h.auditActor(r), "otel.ingestion", "settings", "OTLP ingestion "+action)
	api.WriteJSON(w, http.StatusOK, api.Success(st))
}
