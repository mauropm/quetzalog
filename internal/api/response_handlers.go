package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"quetzalog/internal/response"
	"quetzalog/pkg/api"
)

// ListResponseActions returns the catalog of available analyst actions.
func (h *Handler) ListResponseActions(w http.ResponseWriter, r *http.Request) {
	api.WriteJSON(w, http.StatusOK, api.Success(h.responseRegistry.List()))
}

// ExecuteResponseActionRequest carries a request to run one registered action.
type ExecuteResponseActionRequest struct {
	Action  string          `json:"action"`
	Target  string          `json:"target"`
	Owner   string          `json:"owner"`
	Tag     string          `json:"tag"`
	Points  float64         `json:"points"`
	Title   string          `json:"title"`
	Query   string          `json:"query"`
	URL     string          `json:"url"`
	Event   string          `json:"event"`
	Payload json.RawMessage `json:"payload"`
}

// ExecuteResponseAction executes a registered analyst action and records it
// in both the response ledger and the auth audit trail.
func (h *Handler) ExecuteResponseAction(w http.ResponseWriter, r *http.Request) {
	var req ExecuteResponseActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid request body"))
		return
	}
	if strings.TrimSpace(req.Action) == "" {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("action is required"))
		return
	}

	params := response.ExecuteParams{
		Action:  req.Action,
		Target:  req.Target,
		Owner:   req.Owner,
		Tag:     req.Tag,
		Points:  req.Points,
		Title:   req.Title,
		Query:   req.Query,
		URL:     req.URL,
		Event:   req.Event,
		Payload: req.Payload,
		User:    h.actorUsername(r),
	}

	details, err := h.responseRegistry.Execute(r.Context(), params)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			api.WriteJSON(w, http.StatusNotFound, api.NotFound(err.Error()))
			return
		}
		h.logger.Warn("response action failed", "action", req.Action, "target", req.Target, "error", err)
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest(err.Error()))
		return
	}

	h.logAudit(h.auditActor(r), "response.action", "action:"+req.Action,
		fmt.Sprintf("Executed %s on %s", req.Action, req.Target))

	h.logger.Info("response action executed", "action", req.Action, "target", req.Target, "user", params.User)
	api.WriteJSON(w, http.StatusOK, api.Success(details))
}

// ResponseActionHistory returns the most recent executed actions.
func (h *Handler) ResponseActionHistory(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 200 {
			limit = v
		}
	}
	entries, err := h.responseRegistry.History(r.Context(), limit)
	if err != nil {
		h.logger.Error("response action history", "error", err)
		api.WriteJSON(w, http.StatusInternalServerError, api.InternalServerError("failed to list response actions"))
		return
	}
	if entries == nil {
		entries = []response.Execution{}
	}
	api.WriteJSON(w, http.StatusOK, api.Success(entries))
}
