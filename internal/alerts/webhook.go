package alerts

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// WebhookConfig holds configuration for a webhook endpoint.
type WebhookConfig struct {
	URL         string            `json:"url"`
	Secret      string            `json:"secret"`
	Enabled     bool              `json:"enabled"`
	ContentType string            `json:"content_type"`
	Headers     map[string]string `json:"headers"`
	RetryCount  int               `json:"retry_count"`
	RetryDelay  time.Duration     `json:"retry_delay"`
	Timeout     time.Duration     `json:"timeout"`
	Methods     []string          `json:"methods"`
}

// WebhookResult represents the outcome of a webhook notification.
type WebhookResult struct {
	Success bool   `json:"success"`
	Status  int    `json:"status"`
	Error   string `json:"error,omitempty"`
}

// WebhookNotifier sends alert notifications to webhook endpoints with HMAC signing,
// retry logic, and TLS enforcement.
type WebhookNotifier struct {
	config   WebhookConfig
	client   *http.Client
	mu       sync.Mutex
	failures int
	lastFail time.Time
}

// DefaultWebhookConfig returns a WebhookConfig with sensible defaults.
func DefaultWebhookConfig() WebhookConfig {
	return WebhookConfig{
		ContentType: "application/json",
		RetryCount:  3,
		RetryDelay:  2 * time.Second,
		Timeout:     10 * time.Second,
		Enabled:     true,
		Methods:     []string{"alert.created", "alert.updated", "alert.resolved"},
	}
}

// NewWebhookNotifier creates a WebhookNotifier with the given config.
func NewWebhookNotifier(config WebhookConfig) *WebhookNotifier {
	if config.ContentType == "" {
		config.ContentType = "application/json"
	}
	if config.RetryCount == 0 {
		config.RetryCount = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 2 * time.Second
	}
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	return &WebhookNotifier{
		config: config,
		client: &http.Client{
			Timeout:   config.Timeout,
			Transport: tr,
		},
	}
}

// Notify sends an alert notification to the webhook endpoint.
func (n *WebhookNotifier) Notify(ctx context.Context, alert *Alert, event string) error {
	if !n.config.Enabled {
		return nil
	}

	if !n.isMethodAllowed(event) {
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	payload, err := json.Marshal(map[string]any{
		"event":     event,
		"alert_id":  alert.ID,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"severity":  alert.Severity,
		"title":     alert.Title,
		"status":    alert.Status,
	})
	if err != nil {
		return fmt.Errorf("marshal alert payload: %w", err)
	}

	sig := n.sign(payload)

	newRequest := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, "POST", n.config.URL, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", n.config.ContentType)
		req.Header.Set("X-Quetzalog-Signature", sig)
		req.Header.Set("X-Quetzalog-Event", event)
		for k, v := range n.config.Headers {
			req.Header.Set(k, v)
		}
		return req, nil
	}

	var lastErr error
	for i := 0; i <= n.config.RetryCount; i++ {
		// Rebuild per attempt: retries must resend the full signed payload,
		// never a drained body reader.
		req, err := newRequest()
		if err != nil {
			return fmt.Errorf("create webhook request: %w", err)
		}
		resp, err := n.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("webhook request failed: %w", err)
			n.recordFailure()
			if i < n.config.RetryCount {
				time.Sleep(n.config.RetryDelay * time.Duration(i+1))
				continue
			}
			break
		}

		// Drain and close the body
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		lastErr = fmt.Errorf("webhook unexpected status: %d", resp.StatusCode)

		if resp.StatusCode >= 500 && i < n.config.RetryCount {
			time.Sleep(n.config.RetryDelay * time.Duration(i+1))
			continue
		}
		break
	}

	return lastErr
}

// sign generates an HMAC-SHA256 signature for the payload.
func (n *WebhookNotifier) sign(payload []byte) string {
	if n.config.Secret == "" {
		return ""
	}

	h := hmac.New(sha256.New, []byte(n.config.Secret))
	h.Write(payload)
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

// recordFailure tracks webhook notification failures.
func (n *WebhookNotifier) recordFailure() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.failures++
	n.lastFail = time.Now()
}

// isMethodAllowed checks if the given event is in the allowed methods list.
func (n *WebhookNotifier) isMethodAllowed(event string) bool {
	if len(n.config.Methods) == 0 {
		return true
	}
	for _, m := range n.config.Methods {
		if m == event {
			return true
		}
	}
	return false
}

// ValidateConfig checks if the webhook configuration is valid.
func (c WebhookConfig) ValidateConfig() error {
	if c.URL == "" {
		return fmt.Errorf("webhook URL is required")
	}
	if len(c.URL) <= 8 {
		return fmt.Errorf("webhook URL is too short")
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("webhook timeout must be positive")
	}
	if c.RetryDelay < 0 {
		return fmt.Errorf("webhook retry delay must be non-negative")
	}
	return nil
}

// GetFailureCount returns the number of consecutive failures.
func (n *WebhookNotifier) GetFailureCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.failures
}

// GetLastFailureTime returns the time of the last failure.
func (n *WebhookNotifier) GetLastFailureTime() time.Time {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.lastFail
}

// ResetFailures resets the failure counter.
func (n *WebhookNotifier) ResetFailures() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.failures = 0
	n.lastFail = time.Time{}
}
