package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"quetzalog/internal/correlation"
	"quetzalog/internal/graph"
	"quetzalog/pkg/api"
)

// maxEntityV2Depth mirrors the graph layer's BFS cap.
const maxEntityV2Depth = 4

// validEntityV2States filters the states query parameter.
func validEntityV2States(raw string) []string {
	if raw == "" {
		return nil
	}
	valid := map[string]bool{
		"observed": true, "inferred": true, "potential": true, "blocked": true,
	}
	out := []string{}
	for _, s := range strings.Split(raw, ",") {
		s = strings.TrimSpace(s)
		if valid[s] {
			out = append(out, s)
		}
	}
	return out
}

// ResolveEntitiesV2 resolves a raw string to entity candidates
// (GET /api/v1/entities-v2/resolve?raw=).
func (h *Handler) ResolveEntitiesV2(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("raw")
	if strings.TrimSpace(raw) == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("raw query parameter is required"))
		return
	}
	cands, err := h.graphLayer.Resolve(r.Context(), raw)
	if err != nil {
		h.logger.Error("resolve entities", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to resolve entities"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(cands))
}

// GetEntityV2 returns one entity with aliases, meta, edges and related
// events (GET /api/v1/entities-v2/{type}/{value}).
func (h *Handler) GetEntityV2(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	et := r.PathValue("type")
	val := r.PathValue("value")
	if et == "" || val == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("type and value are required"))
		return
	}

	out := map[string]any{
		"entity":          map[string]any{"type": et, "value": val},
		"aliases":         []any{},
		"relationships":   []any{},
		"related_event_ids": []string{},
	}

	if ent, err := h.store.Graph().GetEntity(ctx, correlation.EntityType(et), val); err == nil && ent != nil {
		out["entity"] = ent
	}
	if ids, err := h.entitiesStore.IdentitiesFor(ctx, et, val); err == nil {
		out["aliases"] = ids
	}
	if meta, err := h.entitiesStore.GetMeta(ctx, et, val); err == nil && meta != nil {
		out["meta"] = meta
	}
	if edges, err := h.entitiesStore.RelationshipsOf(ctx, et, val, 200); err == nil {
		out["relationships"] = edges
	}
	if ids, err := h.store.Graph().GetRelatedEvents(ctx, correlation.EntityType(et), val, 20); err == nil {
		out["related_event_ids"] = ids
	}

	api.WriteJSON(w, http.StatusOK, api.Success(out))
}

// NeighborsV2 performs a state-aware BFS around an entity
// (GET /api/v1/entities-v2/{type}/{value}/neighbors?depth=&states=).
func (h *Handler) NeighborsV2(w http.ResponseWriter, r *http.Request) {
	et := r.PathValue("type")
	val := r.PathValue("value")
	if et == "" || val == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("type and value are required"))
		return
	}
	depth := 2
	if v := r.URL.Query().Get("depth"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			depth = n
		}
	}
	states := validEntityV2States(r.URL.Query().Get("states"))
	nodes, err := h.graphLayer.Neighbors(r.Context(), graph.NodeRef{Type: et, Value: val}, depth, states)
	if err != nil {
		h.logger.Error("entity neighbors", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to traverse entity graph"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(nodes))
}

// entityAliasBody is the link/unlink request body.
type entityAliasBody struct {
	CanonicalType  string `json:"canonical_type"`
	CanonicalValue string `json:"canonical_value"`
	AliasType      string `json:"alias_type"`
	AliasValue     string `json:"alias_value"`
}

func (b entityAliasBody) complete() bool {
	return b.CanonicalType != "" && b.CanonicalValue != "" && b.AliasType != "" && b.AliasValue != ""
}

// LinkEntityAlias records an analyst-confirmed alias
// (POST /api/v1/entities-v2/aliases).
func (h *Handler) LinkEntityAlias(w http.ResponseWriter, r *http.Request) {
	var in entityAliasBody
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid alias body"))
		return
	}
	if !in.complete() {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("canonical_type, canonical_value, alias_type and alias_value are required"))
		return
	}
	if err := h.entitiesStore.Link(r.Context(), in.CanonicalType, in.CanonicalValue, in.AliasType, in.AliasValue); err != nil {
		h.logger.Error("link entity alias", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to link entities"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"status": "linked"}))
}

// UnlinkEntityAlias removes an alias row
// (DELETE /api/v1/entities-v2/aliases).
func (h *Handler) UnlinkEntityAlias(w http.ResponseWriter, r *http.Request) {
	var in entityAliasBody
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid alias body"))
		return
	}
	if !in.complete() {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("canonical_type, canonical_value, alias_type and alias_value are required"))
		return
	}
	if err := h.entitiesStore.Unlink(r.Context(), in.CanonicalType, in.CanonicalValue, in.AliasType, in.AliasValue); err != nil {
		if strings.Contains(err.Error(), "not found") {
			api.WriteJSON(w, http.StatusNotFound, api.NotFound("alias not found"))
			return
		}
		h.logger.Error("unlink entity alias", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to unlink entities"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"status": "unlinked"}))
}
