package ai

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"quetzalog/internal/config"
)

// Provider is a provider-agnostic model endpoint. Implementations must treat
// the endpoint as an external, untrusted dependency: no credentials in logs,
// bounded timeouts, structured errors.
type Provider interface {
	// Name returns the stable provider identifier
	// ("openai-compatible", "ollama", "opencode").
	Name() string
	// Analyze sends the analyst prompt and returns the raw model text.
	Analyze(ctx context.Context, req Request) (string, error)
	// Health probes the endpoint (no chat completion, no token cost).
	Health(ctx context.Context) (Health, error)
	// Models lists model identifiers the endpoint offers. ok=false when the
	// provider does not support discovery.
	Models(ctx context.Context) ([]string, bool, error)
}

// Request is everything a provider needs for one analyst chat.
type Request struct {
	System   string
	Prompt   string
	Model    string
	Timeout  time.Duration
	Temp     float64
	// NoTools asks providers that bundle tools (OpenCode) to disable them.
	NoTools bool
}

// Health describes the result of a connection test.
type Health struct {
	OK       bool
	Provider string
	Model    string
	Latency  time.Duration
	// Detail carries a short human-readable explanation (never secrets).
	Detail string
}

// Sentinel errors for provider failures. UI and retry logic key off these.
var (
	ErrAuth         = errors.New("model endpoint rejected the credentials")
	ErrRateLimited  = errors.New("model endpoint is rate limiting requests")
	ErrTimeout      = errors.New("model endpoint timed out")
	ErrUnavailable  = errors.New("model endpoint is unavailable")
	ErrBadResponse  = errors.New("model endpoint returned a malformed response")
	ErrBadConfig    = errors.New("ai analyst is not configured")
)

// IsTransient reports whether a provider error is worth retrying.
func IsTransient(err error) bool {
	return errors.Is(err, ErrTimeout) ||
		errors.Is(err, ErrRateLimited) ||
		errors.Is(err, ErrUnavailable)
}

// NewProvider builds the provider selected by cfg.Provider. Endpoint and
// model are required for every provider; missing configuration yields
// ErrBadConfig so callers can surface a useful UI error.
func NewProvider(cfg config.AIAnalyst) (Provider, error) {
	p := strings.ToLower(strings.TrimSpace(cfg.Provider))
	endpoint := strings.TrimSpace(cfg.Endpoint)
	model := strings.TrimSpace(cfg.Model)
	if endpoint == "" {
		return nil, fmt.Errorf("%w: endpoint is required", ErrBadConfig)
	}
	if model == "" {
		return nil, fmt.Errorf("%w: model is required", ErrBadConfig)
	}
	switch p {
	case "openai", "openai-compatible", "openai_compatible", "":
		return newOpenAIProvider(cfg), nil
	case "ollama":
		// Ollama speaks the OpenAI-compatible API under /v1; normalize a
		// bare host:port endpoint so operators can write either form.
		if !strings.HasSuffix(endpoint, "/v1") {
			endpoint = strings.TrimRight(endpoint, "/") + "/v1"
		}
		c := cfg
		c.Endpoint = endpoint
		c.Provider = "ollama"
		return newOpenAIProvider(c), nil
	case "opencode":
		return newOpenCodeProvider(cfg), nil
	default:
		return nil, fmt.Errorf("%w: unknown provider %q (expected openai-compatible, ollama or opencode)", ErrBadConfig, cfg.Provider)
	}
}
