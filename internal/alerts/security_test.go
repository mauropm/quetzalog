package alerts_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"quetzalog/internal/alerts"
)

// WH-SEC-01: retried webhook deliveries must resend the full signed payload.
// A drained-body retry would deliver empty/unsigned payloads on attempt >=2
// (integrity + reliability defect).
func TestWHSec_RetryResendsFullPayload(t *testing.T) {
	var mu sync.Mutex
	type seen struct {
		body string
		sig  string
	}
	var got []seen

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, seen{body: string(b), sig: r.Header.Get("X-Quetzalog-Signature")})
		mu.Unlock()
		if len(got) < 3 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(202)
	}))
	defer srv.Close()

	cfg := alerts.WebhookConfig{
		URL:        srv.URL,
		Secret:     "test-secret",
		Enabled:    true,
		RetryCount: 2,
		RetryDelay: 5 * time.Millisecond,
		Timeout:    2 * time.Second,
	}
	n := alerts.NewWebhookNotifier(cfg)

	err := n.Notify(context.Background(), &alerts.Alert{ID: "a1", Severity: "high", Title: "t", Status: "new"}, "alert.created")
	if err != nil {
		t.Fatalf("notify: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 3 {
		t.Fatalf("server saw %d deliveries, want 3", len(got))
	}
	for i, g := range got {
		if len(g.body) == 0 {
			t.Errorf("delivery %d had EMPTY body — retry reused drained reader (WH-SEC-01)", i+1)
		}
		if g.sig == "" {
			t.Errorf("delivery %d missing HMAC signature", i+1)
		}
	}
	if got[0].body != got[1].body || got[1].body != got[2].body {
		t.Errorf("retry deliveries differ: %q / %q / %q", got[0].body, got[1].body, got[2].body)
	}
}

// WH-SEC-02: malformed webhook config must fail validation (no SSRF via
// scheme-less/short URLs, no negative retry delays).
func TestWHSec_ConfigValidation(t *testing.T) {
	bad := []alerts.WebhookConfig{
		{URL: "", Timeout: time.Second},
		{URL: "ht", Timeout: time.Second},
		{URL: "://nope", Timeout: time.Second},
		{URL: "http://x", Timeout: 0},
		{URL: "http://x", Timeout: time.Second, RetryDelay: -1},
	}
	for _, c := range bad {
		if err := c.ValidateConfig(); err == nil {
			t.Errorf("invalid webhook config accepted: %+v", c)
		}
	}
	good := alerts.WebhookConfig{URL: "https://example.invalid/hook", Timeout: time.Second, RetryDelay: 0}
	if err := good.ValidateConfig(); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}
