package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"quetzalog/internal/threatintel"
	"quetzalog/pkg/api"
)

// ListIndicators returns the indicator store (GET /api/v1/intel/indicators).
// Query params: type, q (substring), limit.
func (h *Handler) ListIndicators(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := threatintel.ListFilter{
		Type: q.Get("type"),
		Q:    q.Get("q"),
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Limit = n
		}
	}
	list, total, err := h.tiStore.List(r.Context(), f)
	if err != nil {
		h.logger.Error("list indicators", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list indicators"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"indicators": list,
		"total":      total,
	}))
}

// CreateIndicator adds an analyst indicator (POST /api/v1/intel/indicators).
func (h *Handler) CreateIndicator(w http.ResponseWriter, r *http.Request) {
	var in threatintel.InIndicator
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid indicator body"))
		return
	}
	if in.Source == "" {
		in.Source = "analyst"
	}
	ind, err := h.tiStore.Upsert(r.Context(), in)
	if err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(err.Error()))
		return
	}
	srcs, _ := h.tiStore.SourcesOf(r.Context(), ind.ID)
	api.WriteJSON(w, http.StatusCreated, api.Success(map[string]any{
		"indicator": ind,
		"sources":   srcs,
	}))
}

// LookupIndicators resolves a raw value against the store
// (POST /api/v1/intel/indicators/lookup).
func (h *Handler) LookupIndicators(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Value string `json:"value"`
		Type  string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Value == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("value is required"))
		return
	}
	var hits []threatintel.Indicator
	var err error
	if in.Type != "" {
		hits, err = h.tiStore.LookupByType(r.Context(), in.Type, in.Value)
	} else {
		hits, err = h.tiStore.Lookup(r.Context(), in.Value)
	}
	if err != nil {
		h.logger.Error("lookup indicators", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to lookup indicators"))
		return
	}
	correlated := map[string][]string{}
	for _, hit := range hits {
		if ids, err := h.tiStore.CorrelatedIDs(r.Context(), hit.ID, 10); err == nil {
			correlated[hit.ID] = ids
		}
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"value":      in.Value,
		"hits":       hits,
		"correlated": correlated,
	}))
}

// GetIndicatorByValue returns one indicator by type+value
// (GET /api/v1/intel/indicators/{type}/{value}).
func (h *Handler) GetIndicatorByValue(w http.ResponseWriter, r *http.Request) {
	typ := r.PathValue("type")
	value := r.PathValue("value")
	hits, err := h.tiStore.LookupByType(r.Context(), typ, value)
	if err != nil {
		h.logger.Error("get indicator", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to load indicator"))
		return
	}
	if len(hits) == 0 {
		api.WriteJSON(w, http.StatusNotFound, api.NotFound("indicator not found"))
		return
	}
	ind := hits[0]
	srcs, _ := h.tiStore.SourcesOf(r.Context(), ind.ID)
	ids, _ := h.tiStore.CorrelatedIDs(r.Context(), ind.ID, 50)
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"indicator":  ind,
		"sources":    srcs,
		"correlated": ids,
	}))
}

// ListTIProviders lists registered TI providers with their state
// (GET /api/v1/threat-intel/providers).
func (h *Handler) ListTIProviders(w http.ResponseWriter, r *http.Request) {
	states, err := h.tiStore.ProviderStates(r.Context())
	if err != nil {
		h.logger.Error("provider states", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to load provider state"))
		return
	}
	byName := map[string]threatintel.ProviderState{}
	for _, s := range states {
		byName[s.Provider] = s
	}
	out := []map[string]any{}
	for _, name := range h.tiRegistry.Names() {
		st := byName[name]
		entry := map[string]any{"name": name, "registered": true}
		if st.Provider != "" {
			entry["last_sync"] = st.LastSync
			entry["last_status"] = st.LastStatus
			entry["last_error"] = st.LastError
			entry["indicator_count"] = st.IndicatorCount
		}
		out = append(out, entry)
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"providers": out}))
}

// SyncTIProvider triggers a one-shot provider sync
// (POST /api/v1/threat-intel/providers/{name}/sync).
func (h *Handler) SyncTIProvider(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	n, err := h.tiRegistry.Sync(r.Context(), name)
	if err != nil {
		api.WriteJSON(w, http.StatusBadGateway, api.Error(http.StatusBadGateway, err.Error()))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"provider":     name,
		"imported":     n,
	}))
}

// TISyncStatus returns provider sync state (GET /api/v1/threat-intel/sync/status).
func (h *Handler) TISyncStatus(w http.ResponseWriter, r *http.Request) {
	states, err := h.tiStore.ProviderStates(r.Context())
	if err != nil {
		h.logger.Error("sync status", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to load sync status"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"providers": states}))
}

// ListActors lists threat actors (GET /api/v1/threat-actors).
func (h *Handler) ListActors(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	list, err := h.tiStore.ListActors(r.Context(), limit)
	if err != nil {
		h.logger.Error("list actors", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list actors"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"actors": list}))
}

// GetActor returns one actor with its indicators (GET /api/v1/threat-actors/{id}).
func (h *Handler) GetActor(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, err := h.tiStore.GetActor(r.Context(), id)
	if err != nil {
		if err == threatintel.ErrNotFound {
			api.WriteJSON(w, http.StatusNotFound, api.NotFound("actor not found"))
			return
		}
		h.logger.Error("get actor", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to load actor"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(a))
}

// ListCampaigns lists campaigns (GET /api/v1/campaigns).
func (h *Handler) ListCampaigns(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	list, err := h.tiStore.ListCampaigns(r.Context(), limit)
	if err != nil {
		h.logger.Error("list campaigns", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list campaigns"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"campaigns": list}))
}

// ListMalware lists malware families (GET /api/v1/malware).
func (h *Handler) ListMalware(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	list, err := h.tiStore.ListMalware(r.Context(), limit)
	if err != nil {
		h.logger.Error("list malware", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list malware"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"malware_families": list}))
}
