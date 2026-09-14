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
	"sync"
	"time"

	"quetzalog/internal/config"
)

// openCodeProvider talks to an `opencode serve` HTTP server (OpenCode Go /
// OpenCode Zen). The API is session-based, not chat-completions-based:
//
//	POST /session                       → create a session
//	POST /session/{id}/message          → send the analyst prompt, wait for reply
//	DELETE /session/{id}                → clean up
//	GET  /global/health                 → connection test
//	GET  /config/providers              → model discovery
//
// Authentication is HTTP basic auth (server protected by
// OPENCODE_SERVER_PASSWORD; user defaults to "opencode").
type openCodeProvider struct {
	base     string
	user     string
	password string
	model    string // "provider/model" form
	client   *http.Client

	mu       sync.Mutex
	toolIDs  []string
	toolsSet bool // tool IDs were resolved (may be empty on error)
}

func newOpenCodeProvider(cfg config.AIAnalyst) *openCodeProvider {
	user := strings.TrimSpace(cfg.Username)
	if user == "" {
		user = "opencode"
	}
	return &openCodeProvider{
		base:     strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/"),
		user:     user,
		password: cfg.APIKey,
		model:    strings.TrimSpace(cfg.Model),
		client:   &http.Client{},
	}
}

func (p *openCodeProvider) Name() string { return "opencode" }

func (p *openCodeProvider) doJSON(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		buf, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if p.password != "" {
		req.SetBasicAuth(p.user, p.password)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return fmt.Errorf("%w: %s", ErrTimeout, p.base)
		}
		return fmt.Errorf("%w: %s", ErrUnavailable, p.base)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("read opencode response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return classifyHTTPStatus(resp.StatusCode, string(data))
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("%w: opencode returned non-JSON body", ErrBadResponse)
		}
	}
	return nil
}

// parseModelRef splits a "provider/model" reference.
func (p *openCodeProvider) parseModelRef() (providerID, modelID string, err error) {
	ref := strings.TrimSpace(p.model)
	i := strings.Index(ref, "/")
	if i <= 0 || i == len(ref)-1 {
		return "", "", fmt.Errorf("%w: OpenCode model must use the \"provider/model\" form, e.g. \"opencode/qwen3.8\"", ErrBadConfig)
	}
	return ref[:i], ref[i+1:], nil
}

// toolsAllFalse builds a tools map disabling every tool the server knows,
// so the analysis session cannot touch files, shell or network. Best effort:
// if the tool list is unavailable the message is sent without the map.
func (p *openCodeProvider) toolsAllFalse(ctx context.Context) map[string]bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.toolsSet {
		if len(p.toolIDs) == 0 {
			return nil
		}
		m := make(map[string]bool, len(p.toolIDs))
		for _, id := range p.toolIDs {
			m[id] = false
		}
		return m
	}
	var ids []string
	err := p.doJSON(ctx, http.MethodGet, "/experimental/tool/ids", nil, &ids)
	p.toolIDs = ids // may stay nil
	p.toolsSet = true
	if err != nil || len(ids) == 0 {
		return nil
	}
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = false
	}
	return m
}

type ocSession struct {
	ID string `json:"id"`
}

type ocMessageRequest struct {
	Parts  []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"parts"`
	System string        `json:"system,omitempty"`
	Model  *ocModelRef   `json:"model,omitempty"`
	Tools  map[string]bool `json:"tools,omitempty"`
}

type ocModelRef struct {
	ProviderID string `json:"providerID"`
	ModelID    string `json:"modelID"`
}

type ocMessageResponse struct {
	Info struct {
		Error json.RawMessage `json:"error"`
	} `json:"info"`
	Parts []struct {
		Type      string `json:"type"`
		Text      string `json:"text"`
		Synthetic bool   `json:"synthetic"`
		Ignored   bool   `json:"ignored"`
	} `json:"parts"`
}

// Analyze runs the analyst prompt through a fresh OpenCode session.
func (p *openCodeProvider) Analyze(ctx context.Context, req Request) (string, error) {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	provID, modelID, err := p.parseModelRef()
	if err != nil {
		return "", err
	}

	var ses ocSession
	if err := p.doJSON(ctx, http.MethodPost, "/session", map[string]any{
		"title": "quetzalog-ai-analyst",
	}, &ses); err != nil {
		return "", fmt.Errorf("opencode create session: %w", err)
	}
	defer func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer ccancel()
		_ = p.doJSON(cctx, http.MethodDelete, "/session/"+ses.ID, nil, nil)
	}()

	var out ocMessageResponse
	mreq := ocMessageRequest{
		Parts: []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}{{Type: "text", Text: req.Prompt}},
		System: req.System,
		Model:  &ocModelRef{ProviderID: provID, ModelID: modelID},
	}
	if req.NoTools {
		mreq.Tools = p.toolsAllFalse(ctx)
	}
	if err := p.doJSON(ctx, http.MethodPost, "/session/"+ses.ID+"/message", &mreq, &out); err != nil {
		return "", err
	}

	if len(out.Info.Error) > 0 && string(out.Info.Error) != "null" {
		return "", mapOpenCodeError(out.Info.Error)
	}

	var texts []string
	for _, part := range out.Parts {
		if part.Type != "text" || part.Synthetic || part.Ignored {
			continue
		}
		if strings.TrimSpace(part.Text) != "" {
			texts = append(texts, part.Text)
		}
	}
	content := strings.TrimSpace(strings.Join(texts, "\n"))
	if content == "" {
		return "", fmt.Errorf("%w: opencode returned no text content", ErrBadResponse)
	}
	return content, nil
}

// mapOpenCodeError converts an OpenCode error payload ({name, data}) onto
// the provider sentinel errors where the mapping is unambiguous.
func mapOpenCodeError(raw json.RawMessage) error {
	var e struct {
		Name string `json:"name"`
		Data struct {
			Message    string `json:"message"`
			StatusCode int    `json:"statusCode"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		return fmt.Errorf("opencode model error: %s", truncateBytes(string(raw), 300))
	}
	msg := e.Data.Message
	if msg == "" {
		msg = e.Name
	}
	switch {
	case e.Name == "ProviderAuthError":
		return fmt.Errorf("%w: %s", ErrAuth, msg)
	case e.Name == "APIError":
		switch {
		case e.Data.StatusCode == 401 || e.Data.StatusCode == 403:
			return fmt.Errorf("%w: %s", ErrAuth, msg)
		case e.Data.StatusCode == 429:
			return fmt.Errorf("%w: %s", ErrRateLimited, msg)
		default:
			return fmt.Errorf("%w: %s", ErrUnavailable, msg)
		}
	case e.Name == "StructuredOutputError":
		return fmt.Errorf("%w: %s", ErrBadResponse, msg)
	default:
		return fmt.Errorf("opencode model error: %s", msg)
	}
}

// Health probes GET /global/health.
func (p *openCodeProvider) Health(ctx context.Context) (Health, error) {
	start := time.Now()
	h := Health{Provider: "opencode"}
	var out struct {
		Healthy bool   `json:"healthy"`
		Version string `json:"version"`
	}
	if err := p.doJSON(ctx, http.MethodGet, "/global/health", nil, &out); err != nil {
		h.Latency = time.Since(start)
		h.Detail = err.Error()
		return h, err
	}
	h.Latency = time.Since(start)
	h.OK = out.Healthy
	h.Model = p.model
	h.Detail = "opencode server v" + out.Version
	return h, nil
}

// Models lists "provider/model" identifiers from GET /config/providers.
func (p *openCodeProvider) Models(ctx context.Context) ([]string, bool, error) {
	var out struct {
		Providers []struct {
			ID     string                  `json:"id"`
			Models map[string]struct {
				Name string `json:"name"`
			} `json:"models"`
		} `json:"providers"`
	}
	if err := p.doJSON(ctx, http.MethodGet, "/config/providers", nil, &out); err != nil {
		return nil, false, err
	}
	var ids []string
	for _, prov := range out.Providers {
		for id := range prov.Models {
			ids = append(ids, prov.ID+"/"+id)
		}
	}
	return ids, true, nil
}
