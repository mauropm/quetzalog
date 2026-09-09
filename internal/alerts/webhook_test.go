package alerts

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWebhookNotifier_SignatureValid(t *testing.T) {
	secret := "my-secret-key"
	config := WebhookConfig{
		URL:         "http://localhost:9999/webhook",
		Secret:      secret,
		Enabled:     true,
		ContentType: "application/json",
		RetryCount:  0,
		Timeout:     5 * time.Second,
		Methods:     []string{"alert.created"},
	}

	notifier := NewWebhookNotifier(config)

	testPayload := []byte(`{"event":"alert.created"}`)
	sig := notifier.sign(testPayload)

	if sig == "" {
		t.Fatal("expected non-empty signature")
	}

	if !strings.HasPrefix(sig, "sha256=") {
		t.Fatalf("expected signature to start with 'sha256=', got: %s", sig)
	}

	h := hmac.New(sha256.New, []byte(secret))
	h.Write(testPayload)
	expectedSig := "sha256=" + hex.EncodeToString(h.Sum(nil))

	if sig != expectedSig {
		t.Fatalf("expected signature %s, got %s", expectedSig, sig)
	}
}

func TestWebhookNotifier_ConfigDefault(t *testing.T) {
	config := DefaultWebhookConfig()

	if config.ContentType != "application/json" {
		t.Errorf("expected default content type 'application/json', got '%s'", config.ContentType)
	}
	if config.RetryCount != 3 {
		t.Errorf("expected default retry count 3, got %d", config.RetryCount)
	}
	if config.RetryDelay != 2*time.Second {
		t.Errorf("expected default retry delay 2s, got %v", config.RetryDelay)
	}
	if config.Timeout != 10*time.Second {
		t.Errorf("expected default timeout 10s, got %v", config.Timeout)
	}
	if !config.Enabled {
		t.Error("expected enabled to be true by default")
	}
	if len(config.Methods) != 3 {
		t.Errorf("expected 3 default methods, got %d", len(config.Methods))
	}
	expectedMethods := []string{"alert.created", "alert.updated", "alert.resolved"}
	for _, m := range expectedMethods {
		found := false
		for _, cm := range config.Methods {
			if cm == m {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected default method %s in %v", m, config.Methods)
		}
	}
}

func TestWebhookNotifier_URLValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  WebhookConfig
		wantErr bool
	}{
		{
			name:    "empty URL",
			config:  WebhookConfig{URL: "", Timeout: 10 * time.Second},
			wantErr: true,
		},
		{
			name:    "too short URL",
			config:  WebhookConfig{URL: "http://a", Timeout: 10 * time.Second},
			wantErr: true,
		},
		{
			name:    "valid URL",
			config:  WebhookConfig{URL: "http://localhost:9999/webhook", Timeout: 10 * time.Second},
			wantErr: false,
		},
		{
			name:    "HTTPS URL",
			config:  WebhookConfig{URL: "https://hooks.example.com/alerts", Timeout: 10 * time.Second},
			wantErr: false,
		},
		{
			name:    "zero timeout",
			config:  WebhookConfig{URL: "http://localhost:9999/webhook", Timeout: 0},
			wantErr: true,
		},
		{
			name:    "negative retry delay",
			config:  WebhookConfig{URL: "http://localhost:9999/webhook", Timeout: 10 * time.Second, RetryDelay: -1},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.ValidateConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWebhookNotifier_DisabledNotifiesNothing(t *testing.T) {
	config := WebhookConfig{
		URL:        "http://localhost:9999/webhook",
		Enabled:    false,
		Timeout:    5 * time.Second,
		Methods:    []string{"alert.created"},
		RetryCount: 0,
	}

	notifier := NewWebhookNotifier(config)
	alert := &Alert{
		ID:       "test-alert-1",
		Title:    "Test Alert",
		Severity: "high",
		Status:   "new",
	}

	err := notifier.Notify(nil, alert, "alert.created")
	if err != nil {
		t.Errorf("expected no error when disabled, got: %v", err)
	}
}

func TestWebhookNotifier_MethodFiltering(t *testing.T) {
	var mu sync.Mutex
	var receivedEvent string
	var receivedSig string

	config := WebhookConfig{
		URL:         "http://localhost:9999/webhook",
		Secret:      "test-secret",
		Enabled:     true,
		Timeout:     5 * time.Second,
		Methods:     []string{"alert.created", "alert.resolved"},
		RetryCount:  0,
		ContentType: "application/json",
	}

	alert := &Alert{
		ID:       "test-alert-1",
		Title:    "Method Filter Test",
		Severity: "high",
		Status:   "new",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		r.Body.Close()

		event := r.Header.Get("X-Quetzalog-Event")
		sig := r.Header.Get("X-Quetzalog-Signature")

		mu.Lock()
		receivedEvent = event
		receivedSig = sig
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config.URL = server.URL
	config.RetryCount = 0
	notifier := NewWebhookNotifier(config)

	// Should send alert.created (in methods list)
	err := notifier.Notify(nil, alert, "alert.created")
	if err != nil {
		t.Errorf("expected no error for alert.created, got: %v", err)
	}

	mu.Lock()
	if receivedEvent != "alert.created" {
		t.Errorf("expected event 'alert.created', got: %v", receivedEvent)
	}
	if receivedSig == "" {
		t.Error("expected X-Quetzalog-Signature header")
	}
	mu.Unlock()

	// Should not send alert.updated (not in methods list)
	notifier2 := NewWebhookNotifier(config)
	receivedEvent = ""
	receivedSig = ""
	err = notifier2.Notify(nil, alert, "alert.updated")
	if err != nil {
		t.Errorf("expected no error for non-matching method (silently skipped), got: %v", err)
	}
}

func TestWebhookNotifier_RetryOn500(t *testing.T) {
	config := WebhookConfig{
		URL:         "http://localhost:9999/webhook",
		Enabled:     true,
		Timeout:     5 * time.Second,
		RetryCount:  2,
		RetryDelay:  10 * time.Millisecond,
		Methods:     []string{"alert.created"},
		ContentType: "application/json",
	}

	callCount := 0
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		c := callCount
		mu.Unlock()

		if c < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config.URL = server.URL
	notifier := NewWebhookNotifier(config)

	alert := &Alert{
		ID:       "test-alert-1",
		Title:    "Retry Test",
		Severity: "high",
		Status:   "new",
	}

	err := notifier.Notify(nil, alert, "alert.created")
	if err != nil {
		t.Errorf("expected no error after retry, got: %v", err)
	}

	mu.Lock()
	if callCount != 2 {
		t.Errorf("expected 2 calls (1 failure + 1 success), got %d", callCount)
	}
	mu.Unlock()
}

func TestWebhookNotifier_FailureCounting(t *testing.T) {
	config := WebhookConfig{
		URL:        "http://nonexistent-host.example.local:9999/webhook",
		Enabled:    true,
		Timeout:    5 * time.Millisecond,
		RetryCount: 0,
		Methods:    []string{"alert.created"},
	}

	notifier := NewWebhookNotifier(config)

	if notifier.GetFailureCount() != 0 {
		t.Errorf("expected 0 initial failures, got %d", notifier.GetFailureCount())
	}

	alert := &Alert{
		ID:       "test-alert-1",
		Title:    "Failure Test",
		Severity: "high",
		Status:   "new",
	}

	err := notifier.Notify(nil, alert, "alert.created")
	if err == nil {
		t.Error("expected error for unreachable host")
	}

	failures := notifier.GetFailureCount()
	if failures < 1 {
		t.Errorf("expected at least 1 failure, got %d", failures)
	}

	notifier.ResetFailures()
	if notifier.GetFailureCount() != 0 {
		t.Errorf("expected 0 failures after reset, got %d", notifier.GetFailureCount())
	}

	if !notifier.GetLastFailureTime().IsZero() {
		t.Error("expected zero last failure time after reset")
	}
}
