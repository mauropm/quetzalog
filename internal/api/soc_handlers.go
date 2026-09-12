package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"quetzalog/internal/auth"
	"quetzalog/internal/correlation"
	"quetzalog/internal/events"
	"quetzalog/internal/mitre"
	"quetzalog/internal/risk"
	"quetzalog/pkg/api"
)

// socWindow parses the overview time window from query parameters.
func socWindow(r *http.Request) (start, end time.Time, bucket time.Duration, err error) {
	end = time.Now()
	q := r.URL.Query()
	if s := q.Get("start"); s != "" {
		start = parseQueryParamTime(s)
	}
	if e := q.Get("end"); e != "" {
		end = parseQueryParamTime(e)
	}
	if start.IsZero() {
		switch q.Get("range") {
		case "15m":
			start = end.Add(-15 * time.Minute)
		case "1h":
			start = end.Add(-time.Hour)
		case "6h":
			start = end.Add(-6 * time.Hour)
		case "7d":
			start = end.Add(-7 * 24 * time.Hour)
		case "24h", "":
			start = end.Add(-24 * time.Hour)
		default:
			return time.Time{}, time.Time{}, 0, fmt.Errorf("invalid range %q, expected 15m, 1h, 6h, 24h or 7d", q.Get("range"))
		}
	}
	if !start.Before(end) {
		return time.Time{}, time.Time{}, 0, fmt.Errorf("start must be before end")
	}
	span := end.Sub(start)
	switch {
	case span <= 2*time.Hour:
		bucket = 5 * time.Minute
	case span <= 12*time.Hour:
		bucket = 15 * time.Minute
	case span <= 3*24*time.Hour:
		bucket = time.Hour
	case span <= 14*24*time.Hour:
		bucket = 6 * time.Hour
	default:
		bucket = 24 * time.Hour
	}
	return start, end, bucket, nil
}

// SOCOverview assembles the dashboard payload: event/finding timelines,
// queue posture, detection counts and the top entities.
func (h *Handler) SOCOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start, end, bucket, err := socWindow(r)
	if err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(err.Error()))
		return
	}

	base := events.NewQuery()
	base.Start, base.End = start, end

	evTotal, _ := h.store.Count(ctx, base)
	eps := 0.0
	if span := end.Sub(start).Seconds(); span > 0 {
		eps = float64(evTotal) / span
	}

	evTimeline, err := h.store.Timeline(ctx, start, end, bucket)
	if err != nil {
		h.logger.Error("event timeline", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to build overview"))
		return
	}

	findingPosture, err := h.findingStore.Posture(ctx)
	if err != nil {
		h.logger.Error("finding posture", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to build overview"))
		return
	}
	findingTimeline, err := h.findingStore.Timeline(ctx, start, end, bucket)
	if err != nil {
		h.logger.Error("finding timeline", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to build overview"))
		return
	}

	var detectionTotal, detectionEnabled int
	if rules, err := h.detectionStore.List(ctx); err == nil {
		detectionTotal = len(rules)
		for _, d := range rules {
			if d.Enabled {
				detectionEnabled++
			}
		}
	}

	topUsers, _ := h.riskStore.Top(ctx, "user", 5)
	topHosts, _ := h.riskStore.Top(ctx, "host", 5)
	atRiskUsers, _ := h.riskStore.AtRisk(ctx, "user")
	atRiskHosts, _ := h.riskStore.AtRisk(ctx, "host")

	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"window": map[string]any{
			"start":  start.UTC().Format(time.RFC3339),
			"end":    end.UTC().Format(time.RFC3339),
			"bucket": int64(bucket.Seconds()),
		},
		"events": map[string]any{
			"total":    evTotal,
			"eps":      round2(eps),
			"timeline": evTimeline,
		},
		"findings": map[string]any{
			"posture":  findingPosture,
			"timeline": findingTimeline,
		},
		"detections": map[string]any{
			"total":   detectionTotal,
			"enabled": detectionEnabled,
		},
		"top_entities": map[string]any{
			"risky_users":       topUsers,
			"risky_hosts":       topHosts,
			"active_source_ips": h.topEventValues(ctx, "source_ip", start, end, 5),
			"targeted_hosts":    h.topEventValues(ctx, "host", start, end, 5),
			"at_risk_users":     atRiskUsers,
			"at_risk_hosts":     atRiskHosts,
		},
	}))
}

// topEventValues returns the most frequent non-empty values of a whitelisted
// event column within the window.
func (h *Handler) topEventValues(ctx context.Context, column string, start, end time.Time, limit int) []map[string]any {
	if column != "source_ip" && column != "host" {
		return []map[string]any{}
	}
	rows, err := h.store.DB().QueryContext(ctx,
		`SELECT `+column+` AS v, COUNT(*) AS c
		 FROM events
		 WHERE timestamp >= ? AND timestamp <= ? AND `+column+` != ''
		 GROUP BY `+column+`
		 ORDER BY c DESC
		 LIMIT ?`,
		start, end, limit)
	if err != nil {
		return []map[string]any{}
	}
	defer rows.Close()

	var out []map[string]any
	for rows.Next() {
		var v string
		var c int
		if rows.Scan(&v, &c) == nil {
			out = append(out, map[string]any{"value": v, "count": c})
		}
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out
}

// round2 rounds to two decimals for display.
func round2(v float64) float64 {
	return float64(int64(v*100+0.5)) / 100
}

// riskEntityTypeMap maps UI entity types to their risk-store type.
var riskEntityTypeMap = map[string]string{
	"user": "user",
	"host": "host",
	"ip":   "ip",
}

// ListRiskEntities returns the highest-risk entities of a type.
func (h *Handler) ListRiskEntities(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	entityType := strings.ToLower(r.URL.Query().Get("type"))
	if _, ok := riskEntityTypeMap[entityType]; !ok {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("type must be one of: user, host, ip"))
		return
	}
	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 100 {
			limit = v
		}
	}
	entities, err := h.riskStore.Top(ctx, entityType, limit)
	if err != nil {
		h.logger.Error("top risk entities", "type", entityType, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list risk entities"))
		return
	}
	if entities == nil {
		entities = []risk.EntityRisk{}
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"type":     entityType,
		"entities": entities,
	}))
}

// entityDetail assembles the shared entity payload used by the entity and
// threat-intel endpoints.
func (h *Handler) entityDetail(ctx context.Context, entityType, value string) (map[string]any, bool) {
	out := map[string]any{
		"type":      entityType,
		"value":     value,
		"neighbors": []any{},
	}

	if entity, err := h.store.Graph().GetEntity(ctx, correlation.EntityType(entityType), value); err == nil && entity != nil {
		out["first_seen"] = entity.FirstSeen
		out["last_seen"] = entity.LastSeen
		out["event_count"] = entity.Count
	}

	neighbors, err := h.store.Graph().GetNeighbors(ctx, correlation.EntityType(entityType), value, 2)
	if err == nil && neighbors != nil {
		for _, n := range neighbors {
			out["neighbors"] = append(out["neighbors"].([]any), map[string]any{
				"type":     n.Entity.Type,
				"value":    n.Entity.Value,
				"relation": n.Relation,
			})
		}
	}

	if riskType, ok := riskEntityTypeMap[entityType]; ok && h.riskStore != nil {
		if er, err := h.riskStore.Get(ctx, riskType, value); err == nil && er != nil {
			out["risk"] = er
		}
		if contribs, err := h.riskStore.Contributions(ctx, riskType, value, 20); err == nil && contribs != nil {
			out["risk_contributions"] = contribs
		}
	}

	if related, err := h.findingStore.RelatedByEntity(ctx, entityType, value, 20); err == nil && related != nil {
		out["findings"] = related
	}

	return out, true
}

// GetEntityDetail returns the correlation view of an entity: graph record,
// risk breakdown, related findings and neighbors.
func (h *Handler) GetEntityDetail(w http.ResponseWriter, r *http.Request) {
	entityType := strings.ToLower(r.PathValue("type"))
	value := r.PathValue("value")
	if !correlationEntityTypeOK(entityType) {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("type must be one of: user, host, ip, domain, file, process"))
		return
	}

	detail, _ := h.entityDetail(r.Context(), entityType, value)
	api.WriteJSON(w, http.StatusOK, api.Success(detail))
}

// GetEntityIntel returns the entity detail plus a computed reputation label.
// Reputation is derived, not asserted: it reflects observed risk and open
// findings, so it is safe to display without external intel sources.
func (h *Handler) GetEntityIntel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	entityType := strings.ToLower(r.PathValue("type"))
	value := r.PathValue("value")
	if !correlationEntityTypeOK(entityType) {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("type must be one of: user, host, ip, domain, file, process"))
		return
	}

	detail, _ := h.entityDetail(ctx, entityType, value)

	riskScore := 0.0
	openFindings := 0
	if riskType, ok := riskEntityTypeMap[entityType]; ok && h.riskStore != nil {
		if er, err := h.riskStore.Get(ctx, riskType, value); err == nil && er != nil {
			riskScore = er.RiskScore
		}
		openFindings, _ = h.riskStore.ContributedFindings(ctx, riskType, value)
	}

	reputation := "unknown"
	switch {
	case riskScore >= 100 || openFindings >= 3:
		reputation = "malicious"
	case riskScore >= 30 || openFindings >= 1:
		reputation = "suspicious"
	case riskScore > 0:
		reputation = "benign"
	}

	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"entity":        detail,
		"reputation":    reputation,
		"risk_score":    riskScore,
		"open_findings": openFindings,
	}))
}

// correlationEntityTypeOK validates an entity type against the correlation
// graph vocabulary.
func correlationEntityTypeOK(t string) bool {
	switch t {
	case "ip", "user", "host", "process", "file", "domain", "email", "session", "trace_id":
		return true
	}
	return false
}

// MITRETechniques returns the static ATT&CK technique catalog.
func (h *Handler) MITRETechniques(w http.ResponseWriter, r *http.Request) {
	api.WriteJSON(w, http.StatusOK, api.Success(mitre.Techniques()))
}

// MITRETactics returns the static ATT&CK tactic catalog.
func (h *Handler) MITRETactics(w http.ResponseWriter, r *http.Request) {
	api.WriteJSON(w, http.StatusOK, api.Success(mitre.Tactics()))
}

// MITREActive lists techniques currently in play, derived from open findings.
func (h *Handler) MITREActive(w http.ResponseWriter, r *http.Request) {
	techniques, err := h.findingStore.ActiveTechniques(r.Context())
	if err != nil {
		h.logger.Error("active techniques", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list active techniques"))
		return
	}

	out := make([]map[string]any, 0, len(techniques))
	for _, t := range techniques {
		entry := map[string]any{
			"tactic":    t.Tactic,
			"technique": t.Technique,
			"count":     t.Count,
		}
		if name, ok := mitre.TacticName(t.Tactic); ok {
			entry["tactic_name"] = name
		}
		if tech, ok := mitre.Lookup(t.Technique); ok {
			entry["technique_name"] = tech.Name
		}
		out = append(out, entry)
	}
	api.WriteJSON(w, http.StatusOK, api.Success(out))
}

// AuditLog returns recent analyst actions. Viewer accounts are excluded so
// the audit trail itself is not discoverable to read-only staff.
func (h *Handler) AuditLog(w http.ResponseWriter, r *http.Request) {
	if u := h.actorUser(r); u != nil && u.Role == auth.RoleViewer {
		api.WriteJSON(w, http.StatusForbidden, api.Forbidden("audit log is not available to the viewer role"))
		return
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 500 {
			limit = v
		}
	}

	entries, err := h.authStore.ListAudit(r.Context(),
		r.URL.Query().Get("user"), r.URL.Query().Get("action"), limit)
	if err != nil {
		h.logger.Error("list audit log", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list audit log"))
		return
	}
	if entries == nil {
		entries = []auth.AuditEntry{}
	}
	api.WriteJSON(w, http.StatusOK, api.Success(entries))
}
