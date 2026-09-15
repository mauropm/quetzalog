package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"quetzalog/internal/assets"
	"quetzalog/pkg/api"
)

// ListAssets returns the asset inventory (GET /api/v1/assets).
// Query params: q (name substring), entity_type, criticality, limit.
func (h *Handler) ListAssets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := assets.ListFilter{
		Q:           q.Get("q"),
		EntityType:  q.Get("entity_type"),
		Criticality: q.Get("criticality"),
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Limit = n
		}
	}
	list, total, err := h.assetsStore.List(r.Context(), f)
	if err != nil {
		h.logger.Error("list assets", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list assets"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"assets": list,
		"total":  total,
	}))
}

// CreateAsset creates an asset (POST /api/v1/assets).
func (h *Handler) CreateAsset(w http.ResponseWriter, r *http.Request) {
	var in assets.Asset
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid asset body"))
		return
	}
	if in.CreatedBy == "" {
		in.CreatedBy = h.actorUsername(r)
	}
	created, err := h.assetsStore.Create(r.Context(), &in)
	if err != nil {
		if assets.IsInvalid(err) {
			api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(err.Error()))
			return
		}
		h.logger.Error("create asset", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to create asset"))
		return
	}
	full, err := h.assetsStore.Get(r.Context(), created.ID)
	if err != nil {
		full = created
	}
	api.WriteJSON(w, http.StatusCreated, api.Success(full))
}

// GetAsset returns one asset with aliases, software and vulnerabilities
// (GET /api/v1/assets/{id}).
func (h *Handler) GetAsset(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, err := h.assetsStore.Get(r.Context(), id)
	if err != nil {
		if err == assets.ErrNotFound {
			api.WriteJSON(w, http.StatusNotFound, api.NotFound("asset not found"))
			return
		}
		h.logger.Error("get asset", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to load asset"))
		return
	}
	vulns, err := h.assetsStore.Vulnerabilities(r.Context(), id)
	if err != nil {
		h.logger.Error("list asset vulnerabilities", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to load asset vulnerabilities"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"asset":           a,
		"vulnerabilities": vulns,
	}))
}

// UpdateAsset applies a partial update (PATCH /api/v1/assets/{id}).
func (h *Handler) UpdateAsset(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in assets.UpdateInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid update body"))
		return
	}
	updated, err := h.assetsStore.Update(r.Context(), id, in)
	if err != nil {
		switch {
		case err == assets.ErrNotFound:
			api.WriteJSON(w, http.StatusNotFound, api.NotFound("asset not found"))
		case assets.IsInvalid(err):
			api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(err.Error()))
		default:
			h.logger.Error("update asset", "error", err)
			api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to update asset"))
		}
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(updated))
}
