package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"quetzalog/pkg/api"
)

type okHandler struct{}

func (okHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func TestAuthMiddleware(t *testing.T) {
	token := "test-token"

	tests := []struct {
		name   string
		value  string
		status int
	}{
		{"missing", "", http.StatusUnauthorized},
		{"wrong scheme", "Basic test-token", http.StatusUnauthorized},
		{"wrong token", "Bearer nope", http.StatusUnauthorized},
		{"valid", "Bearer " + token, http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tc.value != "" {
				req.Header.Set("Authorization", tc.value)
			}
			w := httptest.NewRecorder()
			api.AuthMiddleware(token)(okHandler{}).ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Fatalf("got %d want %d body=%s", w.Code, tc.status, w.Body.String())
			}
		})
	}
}

func TestAuthMiddlewareEmptyTokenAcceptsAll(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	api.AuthMiddleware("")(okHandler{}).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("empty token middleware should allow request, got %d", w.Code)
	}
}

func TestCORSOptions(t *testing.T) {
	h := api.CORS(api.WithAllowedOrigins("https://example.com"))(okHandler{})

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Fatalf("bad CORS origin: %q", w.Header().Get("Access-Control-Allow-Origin"))
	}

	req = httptest.NewRequest("OPTIONS", "/", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("preflight status %d", w.Code)
	}
}

func TestRequestIDMiddleware(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	api.RequestIDMiddleware()(okHandler{}).ServeHTTP(w, req)
	if w.Header().Get("X-Request-Id") == "" {
		t.Fatal("request ID was not generated")
	}

	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Request-Id", "custom-id")
	w = httptest.NewRecorder()
	api.RequestIDMiddleware()(okHandler{}).ServeHTTP(w, req)
	if w.Header().Get("X-Request-Id") != "custom-id" {
		t.Fatalf("request ID not preserved: %q", w.Header().Get("X-Request-Id"))
	}
}

func TestRateLimiter(t *testing.T) {
	h := api.RateLimiter(1, 2)(okHandler{})
	pass := 0
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code == http.StatusOK {
			pass++
		} else if w.Code != http.StatusTooManyRequests {
			t.Fatalf("unexpected status %d", w.Code)
		}
	}
	if pass != 2 {
		t.Fatalf("expected two requests to pass, got %d", pass)
	}
}

func TestRecoveryMiddleware(t *testing.T) {
	handler := api.RecoveryMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("recovery status %d", w.Code)
	}
	var body api.Response
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode recovery body: %v", err)
	}
	if body.Status != http.StatusInternalServerError {
		t.Fatalf("recovery body: %#v", body)
	}
}

func TestLoggingMiddleware(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	api.LoggingMiddleware()(okHandler{}).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("logging middleware status %d", w.Code)
	}
}