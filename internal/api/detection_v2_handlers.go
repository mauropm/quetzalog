package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"quetzalog/internal/detections"
	"quetzalog/internal/findings"
	"quetzalog/pkg/api"
)

// AddFindingFeedback records an analyst label for a finding
// (POST /api/v1/findings/{id}/feedback). false_positive and accepted_risk
// require a reason; labels are per-analyst and replaceable.
func (h *Handler) AddFindingFeedback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	var fb findings.Feedback
	if err := json.NewDecoder(r.Body).Decode(&fb); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid feedback body"))
		return
	}
	fb.FindingID = id
	if fb.Analyst == "" {
		fb.Analyst = h.actorUsername(r)
	}
	if err := h.findingStore.AddFeedback(ctx, &fb); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(err.Error()))
		return
	}

	h.logAudit(h.auditActor(r), "finding.feedback", "finding:"+id,
		"Feedback "+fb.Label+" on finding "+id)
	api.WriteJSON(w, http.StatusCreated, api.Success(&fb))
}

// GetFindingFeedback lists analyst labels for a finding
// (GET /api/v1/findings/{id}/feedback).
func (h *Handler) GetFindingFeedback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	fbs, err := h.findingStore.FeedbackForFinding(ctx, id)
	if err != nil {
		h.logger.Error("list finding feedback", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list feedback"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(fbs))
}

// SetDetectionSuppression explicitly suppresses or restores a detection rule
// (POST /api/v1/detections/{id}/suppression). Suppression is a two-step,
// analyst-initiated action: {suppressed: true} requires a reason.
func (h *Handler) SetDetectionSuppression(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	var in struct {
		Suppressed bool   `json:"suppressed"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid suppression body"))
		return
	}

	analyst := h.actorUsername(r)
	if in.Suppressed {
		if err := h.detectionStore.Suppress(ctx, id, analyst, in.Reason); err != nil {
			api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(err.Error()))
			return
		}
		h.logAudit(h.auditActor(r), "detection.suppress", "detection:"+id,
			"Suppressed detection rule "+id+": "+in.Reason)
	} else {
		if err := h.detectionStore.Unsuppress(ctx, id); err != nil {
			api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(err.Error()))
			return
		}
		h.logAudit(h.auditActor(r), "detection.unsuppress", "detection:"+id,
			"Restored detection rule "+id)
	}

	rule, err := h.detectionStore.GetByID(ctx, id)
	if err != nil {
		api.WriteJSON(w, http.StatusNotFound, api.NotFound("detection not found"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(rule))
}

// DetectionStats reports rolling analyst feedback for one rule's findings
// (GET /api/v1/detections/{id}/stats) — informational in v1, no silent
// weight changes (spec §55).
func (h *Handler) DetectionStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	rule, err := h.detectionStore.GetByID(ctx, id)
	if err != nil {
		api.WriteJSON(w, http.StatusNotFound, api.NotFound("detection not found"))
		return
	}
	stats, err := h.findingStore.FeedbackStatsForDetection(ctx, id)
	if err != nil {
		h.logger.Error("detection feedback stats", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to compute stats"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"detection": rule,
		"feedback":  stats,
	}))
}

// Baselines lists rolling behavioral baselines
// (GET /api/v1/behavioral/baselines?entity_type=&entity_value=&feature=).
func (h *Handler) Baselines(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	where := []string{"1=1"}
	args := []any{}
	if v := q.Get("entity_type"); v != "" {
		where = append(where, "entity_type = ?")
		args = append(args, v)
	}
	if v := q.Get("entity_value"); v != "" {
		where = append(where, "entity_value = ?")
		args = append(args, v)
	}
	if v := q.Get("feature"); v != "" {
		where = append(where, "feature = ?")
		args = append(args, v)
	}
	limit := 100
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := h.store.DB().QueryContext(ctx,
		`SELECT entity_type, entity_value, feature, window_days, mean, stddev, p95, sample_count, last_updated
		 FROM baselines WHERE `+strings.Join(where, " AND ")+`
		 ORDER BY last_updated DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		h.logger.Error("list baselines", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list baselines"))
		return
	}
	defer rows.Close()
	type outRow struct {
		EntityType  string    `json:"entity_type"`
		EntityValue string    `json:"entity_value"`
		Feature     string    `json:"feature"`
		WindowDays  int       `json:"window_days"`
		Mean        float64   `json:"mean"`
		StdDev      float64   `json:"stddev"`
		P95         float64   `json:"p95"`
		SampleCount int       `json:"sample_count"`
		LastUpdated time.Time `json:"last_updated"`
		Trusted     bool      `json:"trusted"`
	}
	out := []outRow{}
	for rows.Next() {
		var o outRow
		if err := rows.Scan(&o.EntityType, &o.EntityValue, &o.Feature, &o.WindowDays, &o.Mean, &o.StdDev, &o.P95, &o.SampleCount, &o.LastUpdated); err != nil {
			h.logger.Error("scan baseline", "error", err)
			continue
		}
		o.Trusted = o.SampleCount >= 20 && o.WindowDays >= 14
		out = append(out, o)
	}
	_ = rows.Err()
	api.WriteJSON(w, http.StatusOK, api.Success(out))
}

// Anomalies lists recent behavioral anomalies
// (GET /api/v1/behavioral/anomalies?entity_type=&entity_value=&limit=).
func (h *Handler) Anomalies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	where := []string{"1=1"}
	args := []any{}
	if v := q.Get("entity_type"); v != "" {
		where = append(where, "entity_type = ?")
		args = append(args, v)
	}
	if v := q.Get("entity_value"); v != "" {
		where = append(where, "entity_value = ?")
		args = append(args, v)
	}
	limit := 50
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := h.store.DB().QueryContext(ctx,
		`SELECT id, entity_type, entity_value, feature, observed, baseline_mean, z, detected_at, detection_id, suppressed_reason
		 FROM anomalies WHERE `+strings.Join(where, " AND ")+`
		 ORDER BY detected_at DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		h.logger.Error("list anomalies", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list anomalies"))
		return
	}
	defer rows.Close()
	type outRow struct {
		ID               string    `json:"id"`
		EntityType       string    `json:"entity_type"`
		EntityValue      string    `json:"entity_value"`
		Feature          string    `json:"feature"`
		Observed         float64   `json:"observed"`
		BaselineMean     float64   `json:"baseline_mean"`
		Z                float64   `json:"z"`
		DetectedAt       time.Time `json:"detected_at"`
		DetectionID      string    `json:"detection_id,omitempty"`
		SuppressedReason string    `json:"suppressed_reason,omitempty"`
	}
	out := []outRow{}
	for rows.Next() {
		var o outRow
		var det sql.NullString
		var suppressed sql.NullString
		if err := rows.Scan(&o.ID, &o.EntityType, &o.EntityValue, &o.Feature, &o.Observed, &o.BaselineMean, &o.Z, &o.DetectedAt, &det, &suppressed); err != nil {
			h.logger.Error("scan anomaly", "error", err)
			continue
		}
		o.DetectionID = det.String
		o.SuppressedReason = suppressed.String
		out = append(out, o)
	}
	_ = rows.Err()
	api.WriteJSON(w, http.StatusOK, api.Success(out))
}

// ScenarioRuns lists active/completed/stale threat-scenario runs
// (GET /api/v1/scenarios).
func (h *Handler) ScenarioRuns(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.scenarioEvaluator == nil {
		api.WriteJSON(w, http.StatusServiceUnavailable, api.ServiceUnavailable("scenario evaluator not available"))
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	runs, err := h.scenarioEvaluator.ListRuns(ctx, limit)
	if err != nil {
		h.logger.Error("list scenario runs", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list scenario runs"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(runs))
}

// ScenarioRun fetches one run with its steps and the what-next list
// (GET /api/v1/scenarios/{id}).
func (h *Handler) ScenarioRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	if h.scenarioEvaluator == nil {
		api.WriteJSON(w, http.StatusServiceUnavailable, api.ServiceUnavailable("scenario evaluator not available"))
		return
	}
	run, steps, whatNext, err := h.scenarioEvaluator.GetRun(ctx, id)
	if err != nil {
		api.WriteJSON(w, http.StatusNotFound, api.NotFound(err.Error()))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{
		"run":        run,
		"steps":      steps,
		"what_next":  whatNext,
	}))
}

// CatalogList lists the built-in detection/hunting catalog entries
// (GET /api/v1/detections/catalog). Filter with ?category=detection|hunting.
func (h *Handler) CatalogList(w http.ResponseWriter, r *http.Request) {
	entries, err := detections.ListCatalog()
	if err != nil {
		h.logger.Error("list catalog", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list catalog"))
		return
	}
	if cat := r.URL.Query().Get("category"); cat != "" {
		filtered := []detections.CatalogEntry{}
		for _, e := range entries {
			if e.Category == cat {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}
	api.WriteJSON(w, http.StatusOK, api.Success(entries))
}

// CatalogInstall installs a catalog entry as a detection rule
// (POST /api/v1/detections/catalog/{name}/install). Each install stamps the
// catalog version so upgrades are detectable; existing rules with the same
// name are upgraded in place (suppression preserved).
func (h *Handler) CatalogInstall(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")
	entry, err := detections.CatalogEntryByName(name)
	if err != nil {
		api.WriteJSON(w, http.StatusNotFound, api.NotFound(err.Error()))
		return
	}
	rule, err := h.detectionStore.InstallCatalog(ctx, entry)
	if err != nil {
		h.logger.Error("install catalog entry", "entry", name, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to install catalog entry"))
		return
	}
	api.WriteJSON(w, http.StatusCreated, api.Success(rule))
}

// DetectionStates lists the persisted correlation/sequence state for a rule
// (GET /api/v1/detections/{id}/states). A stuck sequence must be debuggable,
// not a black box (detection-engine.md §2).
func (h *Handler) DetectionStates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	if h.correlationEngine == nil {
		api.WriteJSON(w, http.StatusServiceUnavailable, api.ServiceUnavailable("correlation engine not available"))
		return
	}
	if _, err := h.detectionStore.GetByID(ctx, id); err != nil {
		api.WriteJSON(w, http.StatusNotFound, api.NotFound("detection not found"))
		return
	}
	states, err := h.correlationEngine.ListStates(ctx, id)
	if err != nil {
		h.logger.Error("list detection states", "id", id, "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list states"))
		return
	}
	api.WriteJSON(w, http.StatusOK, api.Success(states))
}
