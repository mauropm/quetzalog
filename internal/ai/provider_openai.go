package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"quetzalog/internal/config"
)

// openAIProvider talks to any OpenAI-compatible chat-completions endpoint.
// It serves both the generic "openai-compatible" provider and Ollama, which
// exposes the same API under /v1.
type openAIProvider struct {
	base     string // endpoint without trailing slash
	apiKey   string
	model    string
	ollama   bool
	client   *http.Client
	provider string
}

func newOpenAIProvider(cfg config.AIAnalyst) *openAIProvider {
	p := &openAIProvider{
		base:     strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/"),
		apiKey:   cfg.APIKey,
		model:    strings.TrimSpace(cfg.Model),
		client:   &http.Client{}, // per-request timeout via context
		provider: "openai-compatible",
	}
	if strings.ToLower(strings.TrimSpace(cfg.Provider)) == "ollama" {
		p.ollama = true
		p.provider = "ollama"
	}
	return p
}

func (p *openAIProvider) Name() string { return p.provider }

// httpStatusError is a 4xx failure from the model endpoint that is not a
// sentinel condition. The status code is carried so callers can distinguish,
// e.g., a 404 on the API root from a 400 on a bad model id.
type httpStatusError struct {
	status int
	msg    string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("model endpoint returned %d: %s", e.status, e.msg)
}

// classifyHTTPStatus maps provider HTTP failures onto sentinel errors.
func classifyHTTPStatus(status int, body string) error {
	msg := strings.TrimSpace(body)
	if msg == "" {
		msg = http.StatusText(status)
	}
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return fmt.Errorf("%w: %s", ErrAuth, msg)
	case status == http.StatusTooManyRequests:
		return fmt.Errorf("%w: %s", ErrRateLimited, msg)
	case status == http.StatusRequestTimeout || status == http.StatusGatewayTimeout:
		return fmt.Errorf("%w: %s", ErrTimeout, msg)
	case status >= 500:
		return fmt.Errorf("%w: %s", ErrUnavailable, msg)
	default:
		// 4xx (400 unknown model, 404 wrong API root, ...) — configuration
		// problems where blind retries will not help.
		return &httpStatusError{status: status, msg: msg}
	}
}

// doJSON performs one authenticated request against the endpoint. The body
// and any credentials never appear in errors or logs.
//
// OpenAI-compatible servers disagree on the API root: vLLM, TGI and friends
// mount it under /v1, while llama.cpp and others serve it at the root. When
// the configured root answers 404, doJSON retries once under /v1 and
// remembers the working prefix for the lifetime of this provider instance.
func (p *openAIProvider) doJSON(ctx context.Context, method, path string, in, out any) error {
	err := p.doJSONOnce(ctx, method, p.base, path, in, out)

	var hse *httpStatusError
	if errors.As(err, &hse) && hse.status == http.StatusNotFound && !strings.Contains(p.base, "/v1") {
		p.base = strings.TrimRight(p.base, "/") + "/v1"
		err = p.doJSONOnce(ctx, method, p.base, path, in, out)
	}
	return err
}

func (p *openAIProvider) doJSONOnce(ctx context.Context, method, base, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		buf, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if p.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				// The per-request timeout fired: the model was too slow.
				// Classify it as a provider timeout (transient, retryable).
				return fmt.Errorf("%w: request to %s timed out", ErrTimeout, base)
			}
			return ctx.Err() // caller cancelled; not a provider failure
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return fmt.Errorf("%w: %s", ErrTimeout, base)
		}
		return fmt.Errorf("%w: %s", ErrUnavailable, base)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("read model response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return classifyHTTPStatus(resp.StatusCode, string(data))
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("%w: %s returned non-JSON body", ErrBadResponse, p.Name())
		}
	}
	return nil
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model          string        `json:"model"`
	Messages       []chatMessage `json:"messages"`
	Temperature    float64       `json:"temperature"`
	MaxCompletion  any           `json:"max_completion_tokens,omitempty"`
	Stream         bool          `json:"stream"`
	Format         string        `json:"format,omitempty"`
	ResponseFormat *respFormat   `json:"response_format,omitempty"`
}

type respFormat struct {
	Type string `json:"type"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Analyze runs one chat completion and returns the assistant text.
func (p *openAIProvider) Analyze(ctx context.Context, req Request) (string, error) {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cr := chatRequest{
		Model:       req.Model,
		Temperature: 0.2,
		Messages: []chatMessage{
			{Role: "system", Content: req.System},
			{Role: "user", Content: req.Prompt},
		},
	}
	// Ask for JSON output where the API supports it; the response validator
	// remains the source of truth either way.
	if p.ollama {
		cr.Format = "json" // Ollama-native parameter, accepted by /v1 too
	} else {
		cr.ResponseFormat = &respFormat{Type: "json_object"}
	}

	var out chatResponse
	if err := p.doJSON(ctx, http.MethodPost, "/chat/completions", &cr, &out); err != nil {
		return "", err
	}
	if out.Error != nil && out.Error.Message != "" {
		return "", fmt.Errorf("model error: %s", truncateBytes(out.Error.Message, 300))
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("%w: no choices in response", ErrBadResponse)
	}
	content := strings.TrimSpace(out.Choices[0].Message.Content)
	if content == "" {
		return "", fmt.Errorf("%w: empty model content", ErrBadResponse)
	}
	return content, nil
}

// Health checks GET /models (OpenAI-compatible). Some gateways do not
// implement it; in that case a 1-token chat completion proves the endpoint
// answers, at negligible cost.
func (p *openAIProvider) Health(ctx context.Context) (Health, error) {
	start := time.Now()
	h := Health{Provider: p.provider, Model: ""}

	type modelList struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	var list modelList
	err := p.doJSON(ctx, http.MethodGet, "/models", nil, &list)
	if err == nil {
		for _, m := range list.Data {
			if m.ID == "" {
				continue
			}
			if h.Model == "" {
				h.Model = m.ID
			}
		}
		h.Latency = time.Since(start)
		h.OK = true
		h.Detail = fmt.Sprintf("%d models available", len(list.Data))
		return h, nil
	}
	if errors.Is(err, ErrAuth) || errors.Is(err, ErrRateLimited) || errors.Is(err, ErrTimeout) || errors.Is(err, ErrUnavailable) {
		h.Latency = time.Since(start)
		h.Detail = err.Error()
		return h, err
	}
	// 400/404 from /models: fall back to a minimal chat probe.
	h.OK, err = p.chatProbe(ctx)
	h.Latency = time.Since(start)
	if !h.OK {
		h.Detail = err.Error()
		return h, err
	}
	h.Detail = "endpoint answered (model list not supported)"
	return h, nil
}

func (p *openAIProvider) chatProbe(ctx context.Context) (bool, error) {
	probe := chatRequest{
		Model:  p.model,
		Messages: []chatMessage{
			{Role: "user", Content: "Reply with the single word: ok"},
		},
		Temperature:   0,
		MaxCompletion: 1,
	}
	var out chatResponse
	if err := p.doJSON(ctx, http.MethodPost, "/chat/completions", &probe, &out); err != nil {
		return false, err
	}
	return true, nil
}

// Models lists model identifiers via GET /models.
func (p *openAIProvider) Models(ctx context.Context) ([]string, bool, error) {
	type modelList struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	var list modelList
	if err := p.doJSON(ctx, http.MethodGet, "/models", nil, &list); err != nil {
		return nil, false, err
	}
	ids := make([]string, 0, len(list.Data))
	for _, m := range list.Data {
		if m.ID != "" {
			ids = append(ids, m.ID)
		}
	}
	return ids, true, nil
}

func truncateBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
