package api

import (
	"encoding/json"
	"net/http"

	"quetzalog/internal/assets"
	"quetzalog/internal/normalization"
	"quetzalog/pkg/api"
)

// AssetCoverage returns computed telemetry coverage for one asset
// (GET /api/v1/coverage/assets/{id}).
func (h *Handler) AssetCoverage(w http.ResponseWriter, r *http.Request) {
	if h.coverageRunner == nil {
		api.WriteJSON(w, http.StatusServiceUnavailable, api.ServiceUnavailable("coverage runner not available"))
		return
	}
	id := r.PathValue("id")
	cov, err := h.coverageRunner.CoverageFor(r.Context(), id)
	if err != nil {
		api.WriteJSON(w, http.StatusNotFound, api.NotFound("asset not found"))
		return
	}
	rows, err := h.coverageRunner.Rows(r.Context(), id)
	if err != nil {
		h.logger.Error("coverage rows", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to load coverage"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"coverage": cov,
		"rows":     rows,
	}))
}

// CoverageSummary returns coverage for every host asset
// (GET /api/v1/coverage/summary).
func (h *Handler) CoverageSummary(w http.ResponseWriter, r *http.Request) {
	if h.coverageRunner == nil {
		api.WriteJSON(w, http.StatusServiceUnavailable, api.ServiceUnavailable("coverage runner not available"))
		return
	}
	list, _, err := h.coverageRunner.AssetStore().List(r.Context(), assets.ListFilter{})
	if err != nil {
		h.logger.Error("coverage summary list", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list assets"))
		return
	}
	summary := []map[string]any{}
	for _, a := range list {
		cov, err := h.coverageRunner.CoverageFor(r.Context(), a.ID)
		if err != nil {
			continue
		}
		summary = append(summary, map[string]any{
			"asset_id":     a.ID,
			"asset_name":   a.Name,
			"entity_type":  a.EntityType,
			"coverage_pct": cov.CoveragePct,
			"available":    cov.Available,
			"missing":      cov.Missing,
			"stale":        cov.Stale,
		})
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"assets": summary,
		"total":  len(summary),
	}))
}

// MarkCoverageExpected declares that a source class is expected for an asset
// (POST /api/v1/coverage/assets/{id}/expected).
func (h *Handler) MarkCoverageExpected(w http.ResponseWriter, r *http.Request) {
	if h.coverageRunner == nil {
		api.WriteJSON(w, http.StatusServiceUnavailable, api.ServiceUnavailable("coverage runner not available"))
		return
	}
	id := r.PathValue("id")
	var in struct {
		SourceClass string `json:"source_class"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.SourceClass == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("source_class is required"))
		return
	}
	class := normalization.ClassFor(in.SourceClass)
	if class == normalization.ClassGeneric {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("unknown source_class"))
		return
	}
	if err := h.coverageRunner.MarkExpected(r.Context(), id, class); err != nil {
		h.logger.Error("mark coverage expected", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to mark expected"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"asset_id": id, "source_class": class, "expected": true}))
}

// RiskExplain returns an entity's accumulated risk plus the contributions
// that make it up (GET /api/v1/risk/entities/{type}/{value}/explain).
func (h *Handler) RiskExplain(w http.ResponseWriter, r *http.Request) {
	entityType := r.PathValue("type")
	value := r.PathValue("value")
	er, err := h.riskStore.Get(r.Context(), entityType, value)
	if err != nil {
		h.logger.Error("risk explain get", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to load risk"))
		return
	}
	contribs, err := h.riskStore.Contributions(r.Context(), entityType, value, 100)
	if err != nil {
		h.logger.Error("risk explain contributions", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to load contributions"))
		return
	}
	out := map[string]any{
		"entity_type":   entityType,
		"entity_value":  value,
		"risk":          er,
		"contributions": contribs,
	}
	if er == nil {
		out["risk"] = map[string]any{
			"type":       entityType,
			"value":      value,
			"risk_score": 0,
			"findings":   0,
		}
	}
	api.WriteJSON(w, http.StatusOK, api.Success(out))
}
