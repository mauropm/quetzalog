package api

import (
	"encoding/json"
	"net/http"

	"quetzalog/internal/threatmodel"
	"quetzalog/pkg/api"
)

// ThreatModelList lists threat models (GET /api/v1/threat-models).
func (h *Handler) ThreatModelList(w http.ResponseWriter, r *http.Request) {
	list, err := h.tmStore.ListModels(r.Context())
	if err != nil {
		h.logger.Error("list threat models", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list threat models"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(list))
}

// ThreatModelCreate creates an empty model (POST /api/v1/threat-models).
// {name, source?, scope?}.
func (h *Handler) ThreatModelCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name   string `json:"name"`
		Source string `json:"source"`
		Scope  string `json:"scope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Name == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("name is required"))
		return
	}
	m := &threatmodel.Model{Name: in.Name, Source: in.Source, Scope: in.Scope}
	if err := h.tmStore.CreateModel(r.Context(), m); err != nil {
		h.logger.Error("create threat model", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to create threat model"))
		return
	}
	api.WriteJSON(w, http.StatusCreated, api.Success(m))
}

// ThreatModelGet fetches a model with its content
// (GET /api/v1/threat-models/{id}).
func (h *Handler) ThreatModelGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	m, err := h.tmStore.GetModel(ctx, id)
	if err != nil {
		api.WriteJSON(w, http.StatusNotFound, api.NotFound(err.Error()))
		return
	}
	nodes, err := h.tmStore.ListNodes(ctx, id)
	if err != nil {
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError(err.Error()))
		return
	}
	edges, err := h.tmStore.ListEdges(ctx, id)
	if err != nil {
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError(err.Error()))
		return
	}
	threats, err := h.tmStore.ListThreats(ctx, id)
	if err != nil {
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError(err.Error()))
		return
	}
	snapshots, _ := h.tmStore.ListSnapshots(ctx, id)
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"model":     m,
		"nodes":     nodes,
		"edges":     edges,
		"threats":   threats,
		"snapshots": snapshots,
	}))
}

// ThreatModelDelete removes a model (DELETE /api/v1/threat-models/{id}).
func (h *Handler) ThreatModelDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := h.tmStore.GetModel(r.Context(), id); err != nil {
		api.WriteJSON(w, http.StatusNotFound, api.NotFound(err.Error()))
		return
	}
	if err := h.tmStore.DeleteModel(r.Context(), id); err != nil {
		h.logger.Error("delete threat model", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to delete threat model"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"deleted": id}))
}

// ThreatModelRefresh re-derives a telemetry/hybrid model from the current
// telemetry and records a drift snapshot
// (POST /api/v1/threat-models/{id}/refresh). Body may carry
// {"triggered_by": "..."}.
func (h *Handler) ThreatModelRefresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	var in struct {
		TriggeredBy string `json:"triggered_by"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	if in.TriggeredBy == "" {
		in.TriggeredBy = "api"
	}

	m, err := h.tmStore.GetModel(ctx, id)
	if err != nil {
		api.WriteJSON(w, http.StatusNotFound, api.NotFound(err.Error()))
		return
	}
	if m.Source == "analyst" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("analyst models are edited manually; only telemetry/hybrid models can be refreshed"))
		return
	}

	cw, err := threatmodel.LoadCrosswalk()
	if err != nil {
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to load crosswalk"))
		return
	}
	d, err := threatmodel.Derive(ctx, h.store.DB(), h.assetsStore, h.tmCoverage, cw)
	if err != nil {
		h.logger.Error("derive threat model", "model", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to derive threat model"))
		return
	}
	for _, n := range d.Nodes {
		n.ModelID = id
	}
	for _, e := range d.Edges {
		e.ModelID = id
	}
	for _, th := range d.Threats {
		th.ModelID = id
	}
	snap, err := h.tmStore.ReplaceContent(ctx, id, d.Nodes, d.Edges, d.Threats, in.TriggeredBy)
	if err != nil {
		h.logger.Error("replace threat model content", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to refresh threat model"))
		return
	}
	// Map threats → controls from the crosswalk.
	for _, tc := range threatmodel.MapThreatControls(d, id, cw) {
		if err := h.tmStore.UpsertThreatControl(ctx, tc); err != nil {
			h.logger.Warn("map threat control", "error", err)
		}
	}
	_ = m
	api.WriteJSON(w, http.StatusOK, api.Success(snap))
}

// ThreatModelSnapshots lists a model's drift history
// (GET /api/v1/threat-models/{id}/snapshots).
func (h *Handler) ThreatModelSnapshots(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := h.tmStore.GetModel(r.Context(), id); err != nil {
		api.WriteJSON(w, http.StatusNotFound, api.NotFound(err.Error()))
		return
	}
	snapshots, err := h.tmStore.ListSnapshots(r.Context(), id)
	if err != nil {
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list snapshots"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(snapshots))
}

// ThreatControls lists the embedded control catalog
// (GET /api/v1/threat-models/controls).
func (h *Handler) ThreatControls(w http.ResponseWriter, r *http.Request) {
	controls, err := h.tmStore.ListControls(r.Context())
	if err != nil {
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list controls"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(controls))
}
