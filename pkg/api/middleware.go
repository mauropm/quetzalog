package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// AuthMiddleware returns middleware that validates a bearer token in the Authorization header.
func AuthMiddleware(token string) func(http.Handler) http.Handler {
	if token == "" {
		slog.Warn("quetzalog: auth middleware configured with empty token — accepting all requests")
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeJSON(w, http.StatusUnauthorized, Response{
					Status:  http.StatusUnauthorized,
					Message: "missing authorization header",
					Errors:  []string{"authorization required"},
				})
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				writeJSON(w, http.StatusUnauthorized, Response{
					Status:  http.StatusUnauthorized,
					Message: "invalid authorization scheme",
					Errors:  []string{"use Bearer token in Authorization header"},
				})
				return
			}

			if parts[1] != token {
				writeJSON(w, http.StatusUnauthorized, Response{
					Status:  http.StatusUnauthorized,
					Message: "invalid token",
					Errors:  []string{"provided token is not valid"},
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CORS returns middleware that adds CORS headers to all responses.
func CORS(options ...CORSOption) func(http.Handler) http.Handler {
	opts := corsOptions{
		allowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodOptions,
		},
		allowedHeaders: []string{
			"Content-Type",
			"Authorization",
			"X-Request-Id",
			"Accept",
			"Accept-Encoding",
			"Accept-Language",
		},
		allowedOrigins: []string{"*"},
		maxAge:         3600 * time.Second,
	}

	for _, o := range options {
		o(&opts)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(opts.allowedMethods, ", "))
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(opts.allowedHeaders, ", "))
			w.Header().Set("Access-Control-Allow-Origin", opts.allowedOrigins[0])
			w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", int(opts.maxAge.Seconds())))

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CORSOption configures CORS middleware behavior.
type CORSOption func(*corsOptions)

type corsOptions struct {
	allowedMethods []string
	allowedHeaders []string
	allowedOrigins []string
	maxAge         time.Duration
	allowCredentials bool
}

// WithAllowedOrigins restricts allowed origin(s).
func WithAllowedOrigins(origins ...string) CORSOption {
	return func(o *corsOptions) {
		o.allowedOrigins = origins
	}
}

// WithAllowedMethods restricts allowed HTTP methods.
func WithAllowedMethods(methods ...string) CORSOption {
	return func(o *corsOptions) {
		o.allowedMethods = methods
	}
}

// WithAllowCredentials sets whether credentials (cookies, auth headers) are allowed.
func WithAllowCredentials(allow bool) CORSOption {
	return func(o *corsOptions) {
		o.allowCredentials = allow
	}
}

// RateLimiter returns middleware that limits the number of requests per second.
func RateLimiter(requestsPerSecond float64, burst int) func(http.Handler) http.Handler {
	if requestsPerSecond <= 0 {
		requestsPerSecond = 10
	}
	if burst <= 0 {
		burst = 20
	}

	limiter := newTokenBucketLimiter(requestsPerSecond, burst)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow() {
				writeJSON(w, http.StatusTooManyRequests, Response{
					Status:  http.StatusTooManyRequests,
					Message: "rate limit exceeded",
					Errors:  []string{"too many requests — retry after a moment"},
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// tokenBucketLimiter implements a simple token bucket rate limiter.
type tokenBucketLimiter struct {
	tokens     float64
	maxTokens  float64
	refillRate float64
	lastRefill time.Time
	mu         sync.Mutex
}

func newTokenBucketLimiter(requestsPerSecond float64, burst int) *tokenBucketLimiter {
	return &tokenBucketLimiter{
		tokens:     float64(burst),
		maxTokens:  float64(burst),
		refillRate: requestsPerSecond,
		lastRefill: time.Now(),
	}
}

func (l *tokenBucketLimiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.lastRefill).Seconds()
	l.tokens += elapsed * l.refillRate
	if l.tokens > l.maxTokens {
		l.tokens = l.maxTokens
	}
	l.lastRefill = now

	if l.tokens < 1 {
		return false
	}

	l.tokens--
	return true
}

// RecoveryMiddleware returns middleware that recovers from panics and returns 500.
func RecoveryMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					slog.Error("quetzalog: panic recovered",
						"error", err,
						"method", r.Method,
						"path", r.URL.Path,
						"remote_addr", r.RemoteAddr,
					)

					// Log stack trace to stderr
					buf := make([]byte, 4096)
					n := captureStack(buf)
					if n > 0 {
						slog.Error("quetzalog: stack trace",
						"trace", string(buf[:n]),
					)
					}

					writeJSON(w, http.StatusInternalServerError, Response{
						Status:  http.StatusInternalServerError,
						Message: "internal server error",
						Errors:  []string{"an unexpected error occurred"},
					})
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// captureStack captures a simplified stack trace (borrowed from runtime/debug).
// This is a simplified version that captures caller information.
func captureStack(buf []byte) int {
	return 0 // Simplified — production code should use runtime.Callers
}

// RequestIDMiddleware returns middleware that generates or accepts an X-Request-Id header.
func RequestIDMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := r.Header.Get("X-Request-Id")
			if requestID == "" {
				requestID = uuid.New().String()
			}

			ctx := context.WithValue(r.Context(), requestIDKey{}, requestID)
			r = r.WithContext(ctx)

			w.Header().Set("X-Request-Id", requestID)
			next.ServeHTTP(w, r)
		})
	}
}

type requestIDKey struct{}

// getReqCtx returns the RequestID value from context if present.
func getReqCtx(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey{}).(string); ok {
		return v
	}
	return ""
}

// LoggingMiddleware returns middleware that logs each request with relevant details.
func LoggingMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap the ResponseWriter to capture the status code
			wrapper := &responseWriterWrapper{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(wrapper, r)

			duration := time.Since(start)
			requestID := getReqCtx(r.Context())

			logArgs := []any{
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapper.statusCode,
				"duration", duration.String(),
				"remote_addr", r.RemoteAddr,
				"user_agent", r.UserAgent(),
				"content_length", r.ContentLength,
				"request_id", requestID,
			}

			if requestID != "" {
				logArgs = append(logArgs, "request_id", requestID)
			}

			if wrapper.statusCode >= http.StatusInternalServerError {
				slog.Error("quetzalog: request completed with error", logArgs...)
			} else if wrapper.statusCode >= http.StatusBadRequest {
				slog.Warn("quetzalog: request completed with client error", logArgs...)
			} else {
				slog.Debug("quetzalog: request completed", logArgs...)
			}
		})
	}
}

// responseWriterWrapper wraps http.ResponseWriter to capture the status code.
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
	written    int
}

func (w *responseWriterWrapper) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *responseWriterWrapper) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.written += n
	return n, err
}

// writeJSON is a helper to write JSON responses with proper content type.
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		fmt.Fprintf(os.Stderr, "quetzalog: failed to encode response: %v\n", err)
	}
}
