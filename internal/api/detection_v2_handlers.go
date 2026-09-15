package api

import (
	"encoding/json"
	"net/http"

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
