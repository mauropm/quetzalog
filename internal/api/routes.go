package api

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"quetzalog/internal/alerts"
	"quetzalog/internal/auth"
	"quetzalog/internal/config"
	"quetzalog/internal/detections"
	"quetzalog/internal/events"
	"quetzalog/internal/incidents"
	"quetzalog/internal/query"
	"quetzalog/pkg/api"
)

// maxAPIBodyBytes bounds every request body admitted by the management API.
const maxAPIBodyBytes int64 = 50 * 1024 * 1024

// loginRateLimit config: refills per second and burst per client IP.
const (
	loginRatePerSecond = 5.0
	loginRateBurst     = 30.0
)

// SetupRouter wires up all HTTP API endpoints and applies middleware.
func SetupRouter(cfg config.Config, store *events.Store, searchSvc *query.Service, alertStore *alerts.Store, incidentStore *incidents.Store, detectionStore *detections.Store, authStore *auth.Store, logger *slog.Logger) (http.Handler, error) {
	if authStore == nil {
		authStore = auth.NewStore(nil)
	} else if err := authStore.EnsureSchema(context.Background()); err != nil {
		return nil, fmt.Errorf("initialize auth schema: %w", err)
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
	h = apiTokenAuth(h, cfg, authStore)
	h = loginRateLimit(h)
	h = securityHeaders(h)
	h = bodyLimit(h, maxAPIBodyBytes)
	h = api.RecoveryMiddleware()(h)
	h = api.LoggingMiddleware()(h)
	h = api.CORS()(h)

	if cfg.Auth.Enabled && cfg.Auth.APIToken == "" && len(cfg.Auth.HECTokens) == 0 {
		logger.Info("no static API/HEC token configured; management endpoints require a bearer token " +
			"obtained from POST /api/v1/login (roles enforced server-side)")
	}

	return h, nil
}

// isWriteMethod reports whether the method mutates state.
func isWriteMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// ingestOnlyPaths are the only management-API routes an HEC (forwarder) token
// may use. HEC tokens must never grant control-plane access.
var ingestOnlyPaths = map[string]bool{
	"/api/v1/events":       true,
	"/api/v1/events/batch": true,
}

// apiTokenAuth enforces the trust boundary for the management API. It never
// opens the API implicitly: when Auth is enabled (the default) a credential
// is always required, except for health and login.
func apiTokenAuth(next http.Handler, cfg config.Config, authStore *auth.Store) http.Handler {
	// The HEC credential list comes from static configuration, so it is
	// flattened once here rather than rebuilt on every authenticated request.
	hecTokens := make([]config.HECToken, 0, len(cfg.Auth.HECTokens)+len(cfg.Splunk.HECTokens))
	hecTokens = append(hecTokens, cfg.Auth.HECTokens...)
	hecTokens = append(hecTokens, cfg.Splunk.HECTokens...)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cleanPath := pathClean(r.URL.Path)

		// Explicit opt-out for trusted local/single-container deployments.
		if !cfg.Auth.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		switch r.Method + " " + cleanPath {
		case "GET /api/v1/health", "POST /api/v1/login":
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" || parts[1] == "" {
			api.WriteJSON(w, http.StatusUnauthorized, api.Unauthorized("missing or malformed bearer token"))
			return
		}
		provided := []byte(parts[1])

		if cfg.Auth.APIToken != "" && subtle.ConstantTimeCompare([]byte(cfg.Auth.APIToken), provided) == 1 {
			next.ServeHTTP(w, r)
			return
		}

		for _, token := range hecTokens {
			if subtle.ConstantTimeCompare([]byte(token.Token), provided) == 1 {
				if r.Method != http.MethodPost || !ingestOnlyPaths[cleanPath] {
					api.WriteJSON(w, http.StatusForbidden, api.Forbidden("HEC tokens may only post events"))
					return
				}
				next.ServeHTTP(w, r)
				return
			}
		}

		// Per-user API tokens (issued at login) with server-side role policy:
		// all roles may read; analyst/admin may write.
		if authStore != nil {
			tok, err := authStore.ValidateAPIToken(r.Context(), parts[1])
			if err == nil {
				user, uerr := authStore.GetUser(r.Context(), tok.UserID)
				if uerr == nil && user != nil && user.Enabled {
					if !isWriteMethod(r.Method) || user.Role == auth.RoleAdmin || user.Role == auth.RoleAnalyst {
						next.ServeHTTP(w, r)
						return
					}
					api.WriteJSON(w, http.StatusForbidden, api.Forbidden("role not permitted for write operations"))
					return
				}
			}
		}

		api.WriteJSON(w, http.StatusUnauthorized, api.Unauthorized("invalid API token"))
	})
}

// pathClean removes "." / ".." segments and duplicate slashes so the
// authorization decision cannot diverge from the router's routing decision.
func pathClean(p string) string {
	p = strings.ReplaceAll(p, "//", "/")
	for strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") {
		p = strings.ReplaceAll(p, "/../", "/")
		p = strings.TrimSuffix(p, "/..")
		p = strings.TrimPrefix(p, "../")
		p = strings.ReplaceAll(p, "//", "/")
	}
	return p
}

// bodyLimit caps the request body at the handler boundary, so endpoints that
// decode r.Body directly cannot be forced to buffer unbounded input.
func bodyLimit(next http.Handler, maxBytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(nil, r.Body, maxBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// securityHeaders applies baseline hardening headers to every API response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		if h.Get("X-Content-Type-Options") == "" {
			h.Set("X-Content-Type-Options", "nosniff")
		}
		if h.Get("X-FRAME-OPTIONS") == "" {
			h.Set("X-FRAME-OPTIONS", "DENY")
		}
		if h.Get("Referrer-Policy") == "" {
			h.Set("Referrer-Policy", "no-referrer")
		}
		if h.Get("Cache-Control") == "" {
			h.Set("Cache-Control", "no-store")
		}
		if h.Get("Content-Security-Policy") == "" {
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		}
		next.ServeHTTP(w, r)
	})
}

// tokenBucket is a small thread-safe token bucket.
type tokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	max        float64
	refillRate float64
	last       time.Time
}

func newTokenBucket(rate, burst float64) *tokenBucket {
	return &tokenBucket{tokens: burst, max: burst, refillRate: rate, last: time.Now()}
}

func (b *tokenBucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.refillRate
	if b.tokens > b.max {
		b.tokens = b.max
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// loginRateLimit throttles credential attempts per source IP to blunt
// brute-force and lockout-abuse, complementing per-account lockout.
func loginRateLimit(next http.Handler) http.Handler {
	var (
		mu      sync.Mutex
		buckets = map[string]*tokenBucket{}
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && pathClean(r.URL.Path) == "/api/v1/login" {
			key := sourceIP(r.RemoteAddr)
			mu.Lock()
			b, ok := buckets[key]
			if !ok {
				if len(buckets) > 4096 {
					buckets = map[string]*tokenBucket{}
				}
				b = newTokenBucket(loginRatePerSecond, loginRateBurst)
				buckets[key] = b
			}
			mu.Unlock()
			if !b.Allow() {
				api.WriteJSON(w, http.StatusTooManyRequests, api.Error(http.StatusTooManyRequests, "too many login attempts — retry later"))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// sourceIP extracts the address without the port from RemoteAddr.
func sourceIP(remote string) string {
	if remote == "" {
		return "unknown"
	}
	i := strings.LastIndex(remote, ":")
	if i <= 0 {
		return remote
	}
	// IPv6 forms like [::1]:port — only strip after the closing bracket.
	if j := strings.LastIndex(remote, "]"); j != -1 && j < i {
		return remote[:i]
	}
	if strings.Contains(remote[:i], ":") { // bare IPv6 without brackets
		return remote
	}
	return remote[:i]
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
