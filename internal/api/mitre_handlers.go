package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"quetzalog/internal/mitre"
	"quetzalog/pkg/api"
)

// ListMappingRules returns the active event→technique mapping rules
// (GET /api/v1/mitre/mapping-rules).
func (h *Handler) ListMappingRules(w http.ResponseWriter, r *http.Request) {
	if h.mitreMapper == nil {
		api.WriteJSON(w, http.StatusServiceUnavailable, api.ServiceUnavailable("mitre mapper not available"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"rules": h.mitreMapper.Rules(),
	}))
}

// RegisterMappingRule adds (or replaces) a runtime mapping rule
// (POST /api/v1/mitre/mapping-rules). Runtime-only; not persisted.
func (h *Handler) RegisterMappingRule(w http.ResponseWriter, r *http.Request) {
	if h.mitreMapper == nil {
		api.WriteJSON(w, http.StatusServiceUnavailable, api.ServiceUnavailable("mitre mapper not available"))
		return
	}
	var rule mitre.Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid rule body"))
		return
	}
	if err := h.mitreMapper.Register(&rule); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(err.Error()))
		return
	}
	api.WriteJSON(w, http.StatusCreated, api.Success(rule))
}

// TechniqueEvents pivots a technique to the events mapped to it
// (GET /api/v1/mitre/techniques/{id}/events).
func (h *Handler) TechniqueEvents(w http.ResponseWriter, r *http.Request) {
	tech, ok := mitre.Lookup(r.PathValue("id"))
	if !ok {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("unknown technique"))
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	// mitre.attack is a JSON array of mapping objects; the technique id
	// appears as a quoted JSON string value inside it.
	rows, err := h.store.DB().QueryContext(r.Context(),
		`SELECT id, timestamp, severity, host, user, source_type, substr(message, 1, 240)
		 FROM events
		 WHERE attributes IS NOT NULL
		   AND json_extract(attributes, '$."mitre"."attack"') LIKE ?
		 ORDER BY timestamp DESC LIMIT ?`,
		"%\""+tech.ID+"\"%", limit)
	if err != nil {
		h.logger.Error("technique events", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to query events"))
		return
	}
	defer rows.Close()
	type mappedEvent struct {
		ID        string         `json:"id"`
		Timestamp time.Time      `json:"timestamp"`
		Severity  string         `json:"severity"`
		Host      sql.NullString `json:"host,omitempty"`
		User      sql.NullString `json:"user,omitempty"`
		Source    sql.NullString `json:"source,omitempty"`
		Message   sql.NullString `json:"message,omitempty"`
	}
	out := []mappedEvent{}
	for rows.Next() {
		var o mappedEvent
		if err := rows.Scan(&o.ID, &o.Timestamp, &o.Severity, &o.Host, &o.User, &o.Source, &o.Message); err != nil {
			h.logger.Error("scan technique event", "error", err)
			continue
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("iterate technique events", "error", err)
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"technique": tech,
		"events":    out,
	}))
}
