package api

import (
	"context"
	"net/http"

	"quetzalog/internal/auth"
)

// actorUser resolves the authenticated user from the request's bearer token.
// It returns nil when the request is not authenticated (e.g. static API token
// or auth disabled).
func (h *Handler) actorUser(r *http.Request) *auth.User {
	hdr := r.Header.Get("Authorization")
	if hdr == "" {
		return nil
	}
	user, err := currentUser(context.WithValue(r.Context(), auth.AuthCtxKey{}, hdr), h.authStore)
	if err != nil {
		return nil
	}
	return user
}

// actorUsername returns the acting analyst's display name, or "anonymous"
// when the request is not user-authenticated.
func (h *Handler) actorUsername(r *http.Request) string {
	if u := h.actorUser(r); u != nil {
		return u.Username
	}
	return "anonymous"
}

// auditActor returns the user ID used for audit entries ("" when the actor
// is not a tracked user, in which case logAudit skips the entry).
func (h *Handler) auditActor(r *http.Request) string {
	if u := h.actorUser(r); u != nil {
		return u.ID
	}
	return ""
}

// logAudit records a no-op-safe audit entry for an analyst action.
func (h *Handler) logAudit(actorID, action, target, detail string) {
	if h.authStore == nil || actorID == "" {
		return
	}
	_ = h.authStore.LogAudit(context.Background(), actorID, action, target, detail, "")
}
