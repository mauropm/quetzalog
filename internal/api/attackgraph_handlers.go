package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"quetzalog/internal/attackgraph"
	"quetzalog/pkg/api"
)

// attackGraphRecompileMinInterval rate-limits Recompute on API access.
const attackGraphRecompileMinInterval = 60 * time.Second

// AttackGraphSnapshot returns a state-labeled graph snapshot
// (GET /api/v1/attack-graph?states=observed,inferred&depth=2&asset=<id>).
func (h *Handler) AttackGraphSnapshot(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	states := []string{}
	if v := r.URL.Query().Get("states"); v != "" {
		for _, s := range strings.Split(v, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				states = append(states, s)
			}
		}
	}
	depth := 2
	if v := r.URL.Query().Get("depth"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			depth = n
		}
	}
	assetID := r.URL.Query().Get("asset")

	// Recompute paths (rate-limited), then snapshot.
	h.recompileAttackGraph(ctx)

	snap, err := h.attackGraph.Snapshot(ctx, states, depth, assetID)
	if err != nil {
		h.logger.Error("attack graph snapshot", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to build attack graph"))
		return
	}
	paths, _ := h.attackGraph.ListPaths(ctx, attackgraph.ListPathsFilter{Limit: 50})
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"generated_at": snap.GeneratedAt,
		"states":       snap.States,
		"nodes":        snap.Nodes,
		"edges":        snap.Edges,
		"truncated":    snap.Truncated,
		"paths":        paths,
	}))
}

var (
	agRecompileMu   sync.Mutex
	agLastRecompile time.Time
)

// recompileAttackGraph triggers a path recompute, rate-limited.
func (h *Handler) recompileAttackGraph(ctx context.Context) {
	agRecompileMu.Lock()
	defer agRecompileMu.Unlock()
	if time.Since(agLastRecompile) < attackGraphRecompileMinInterval {
		return
	}
	agLastRecompile = time.Now()
	if _, err := h.attackGraph.Recompute(ctx); err != nil {
		h.logger.Error("recompile attack graph", "error", err)
	}
}

// AttackGraphPaths lists materialized attack paths
// (GET /api/v1/attack-graph/paths?from=&to=&targets=critical&status=).
func (h *Handler) AttackGraphPaths(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	f := attackgraph.ListPathsFilter{
		From:            q.Get("from"),
		To:              q.Get("to"),
		TargetsCritical: q.Get("targets") == "critical",
		Status:          q.Get("status"),
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			f.Limit = n
		}
	}
	paths, err := h.attackGraph.ListPaths(ctx, f)
	if err != nil {
		h.logger.Error("list attack paths", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list attack paths"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(paths))
}

// AttackGraphPath fetches one path with per-step evidence
// (GET /api/v1/attack-graph/paths/{id}).
func (h *Handler) AttackGraphPath(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	p, err := h.attackGraph.GetPath(ctx, id)
	if err != nil {
		api.WriteJSON(w, http.StatusNotFound, api.NotFound(err.Error()))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(p))
}

// AttackGraphWhatNext answers "what could an attacker do next" for a node
// (GET /api/v1/attack-graph/nodes/{type}/{value}/what-next).
func (h *Handler) AttackGraphWhatNext(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	nodeType := r.PathValue("type")
	nodeValue := r.PathValue("value")
	out, err := h.attackGraph.WhatNext(ctx, nodeType, nodeValue)
	if err != nil {
		h.logger.Error("attack graph what-next", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to build what-next"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(out))
}
