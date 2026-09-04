package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"quetzalog/internal/alerts"
	"quetzalog/internal/auth"
	"quetzalog/internal/config"
	"quetzalog/internal/detections"
	"quetzalog/internal/events"
	"quetzalog/internal/incidents"
	"quetzalog/internal/query"
	"quetzalog/pkg/api"
)

// SetupRouter wires up all HTTP API endpoints and applies middleware.
func SetupRouter(cfg config.Config, store *events.Store, searchSvc *query.Service, alertStore *alerts.Store, incidentStore *incidents.Store, detectionStore *detections.Store, authStore *auth.Store, logger *slog.Logger) http.Handler {
	if authStore == nil {
		authStore = auth.NewStore(nil)
	}
	handler := NewHandler(cfg, store, searchSvc, alertStore, incidentStore, detectionStore, authStore, logger)

	mux := http.NewServeMux()

	// Health & Stats
	mux.HandleFunc("GET /api/v1/health", handler.Health)
	mux.HandleFunc("GET /api/v1/stats", handler.Stats)

	// Events
	mux.HandleFunc("POST /api/v1/events", handler.CreateEvent)
	mux.HandleFunc("POST /api/v1/events/batch", handler.CreateBatchEvents)
	mux.HandleFunc("GET /api/v1/events", handler.ListEvents)
	mux.HandleFunc("GET /api/v1/events/{id}", handler.GetEvent)
	mux.HandleFunc("DELETE /api/v1/events/{id}", handler.DeleteEvent)

	// Search
	mux.HandleFunc("POST /api/v1/search", handler.Search)

	// Alerts
	mux.HandleFunc("GET /api/v1/alerts", handler.ListAlerts)
	mux.HandleFunc("GET /api/v1/alerts/{id}", handler.GetAlert)
	mux.HandleFunc("POST /api/v1/alerts/{id}/acknowledge", handler.AcknowledgeAlert)
	mux.HandleFunc("POST /api/v1/alerts/{id}/resolve", handler.ResolveAlert)
	mux.HandleFunc("POST /api/v1/alerts/{id}/notes", handler.AddNotesToAlert)

	// Incidents
	mux.HandleFunc("GET /api/v1/incidents", handler.ListIncidents)
	mux.HandleFunc("POST /api/v1/incidents", handler.CreateIncident)
	mux.HandleFunc("GET /api/v1/incidents/{id}", handler.GetIncident)
	mux.HandleFunc("POST /api/v1/incidents/{id}/acknowledge", handler.AcknowledgeIncident)
	mux.HandleFunc("POST /api/v1/incidents/{id}/resolve", handler.ResolveIncident)

	// Detections
	mux.HandleFunc("GET /api/v1/detections", handler.ListDetections)
	mux.HandleFunc("POST /api/v1/detections", handler.CreateDetection)
	mux.HandleFunc("PUT /api/v1/detections/{id}", handler.UpdateDetection)
	mux.HandleFunc("DELETE /api/v1/detections/{id}", handler.DeleteDetection)
	mux.HandleFunc("POST /api/v1/detections/{id}/exec", handler.ExecuteDetection)

	// ─────────────────────────────────────────────
	// Authentication & User Management
	// ─────────────────────────────────────────────
	mux.HandleFunc("POST /api/v1/login", handler.Login)
	mux.Handle("POST /api/v1/logout", authAuth(handler.Logout))
	mux.Handle("GET /api/v1/users/me", authAuth(handler.GetMe))
	mux.Handle("PUT /api/v1/users/me/password", authAuth(handler.UpdateMyPassword))
	mux.Handle("GET /api/v1/users", adminAuth(handler.ListUsers))
	mux.Handle("POST /api/v1/users", adminAuth(handler.CreateUser))
	mux.Handle("PUT /api/v1/users/{id}", adminAuth(handler.UpdateUser))
	mux.Handle("DELETE /api/v1/users/{id}", adminAuth(handler.DeleteUser))
	mux.Handle("POST /api/v1/users/{id}/password", adminAuth(handler.UpdateUserPassword))

	// Wrap with middleware (order matters: outermost first)
	var h http.Handler = mux
	h = api.RecoveryMiddleware()(h)
	h = api.LoggingMiddleware()(h)
	h = api.CORS()(h)

	return h
}

// authAuth applies authentication middleware to a handler.
func authAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			api.WriteJSON(w, http.StatusUnauthorized, api.Unauthorized("missing authorization header"))
			return
		}
		ctx := context.WithValue(r.Context(), auth.AuthCtxKey{}, authHeader)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// adminAuth applies authentication + admin role check middleware.
func adminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			api.WriteJSON(w, http.StatusUnauthorized, api.Unauthorized("missing authorization header"))
			return
		}
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			api.WriteJSON(w, http.StatusUnauthorized, api.Unauthorized("invalid authorization scheme"))
			return
		}
		ctx := context.WithValue(r.Context(), auth.AuthCtxKey{}, authHeader)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
