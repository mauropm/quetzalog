package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"quetzalog/internal/config"
)

// TestOpenAIV1PrefixAutoDetect covers servers that mount the OpenAI API
// under /v1 (vLLM, TGI, ...) while the operator configures the bare host.
func TestOpenAIV1PrefixAutoDetect(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/models":
			fmt.Fprint(w, `{"data":[{"id":"qwen3.8"}]}`)
		case "/v1/chat/completions":
			fmt.Fprint(w, `{"choices":[{"message":{"role":"assistant","content":"{\"title\":\"ok\"}"}}]}`)
		default:
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		}
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	// No /v1 in the configured endpoint — like a real DGX Spark / vLLM.
	p, err := NewProvider(config.AIAnalyst{
		Provider: "openai-compatible",
		Endpoint: srv.URL,
		Model:    "qwen3.8",
	})
	if err != nil {
		t.Fatal(err)
	}

	out, err := p.Analyze(context.Background(), Request{Prompt: "x", Model: "qwen3.8", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("analyze with bare host (v1 auto-detect): %v", err)
	}
	if out != `{"title":"ok"}` {
		t.Errorf("content: %q", out)
	}
	if op, ok := p.(*openAIProvider); !ok || op.base != srv.URL+"/v1" {
		t.Errorf("base not pinned to /v1 after detection: %#v", p)
	}

	ids, ok, err := p.Models(context.Background())
	if err != nil || !ok || len(ids) != 1 || ids[0] != "qwen3.8" {
		t.Errorf("models after detection: %v %v %v", ids, ok, err)
	}

	health, err := p.Health(context.Background())
	if err != nil || !health.OK {
		t.Errorf("health after detection: %+v %v", health, err)
	}
}

// fakeOpenAI is an OpenAI-compatible chat completions test server.
type fakeOpenAI struct {
	t           *testing.T
	status      int
	latency     time.Duration
	content     string
	rawResponse string
	key         string // expected Authorization key ("" = none)
	calls       int64
	lastAuth    atomic.Value // string
	lastBody    atomic.Value // string
}

func newFakeOpenAI(t *testing.T, content string) *fakeOpenAI {
	f := &fakeOpenAI{t: t, status: 200, content: content}
	return f
}

func (f *fakeOpenAI) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&f.calls, 1)
		if r.Header.Get("Authorization") != "" {
			f.lastAuth.Store(r.Header.Get("Authorization"))
		}
		var body any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.lastBody.Store(fmt.Sprintf("%v", body))

		if f.latency > 0 {
			time.Sleep(f.latency)
		}
		if f.key != "" && r.Header.Get("Authorization") != "Bearer "+f.key {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":{"message":"invalid api key"}}`)
			return
		}
		if f.status != 200 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(f.status)
			fmt.Fprint(w, `{"error":{"message":"provider says no"}}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if f.rawResponse != "" {
			fmt.Fprint(w, f.rawResponse)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{
				"message": map[string]any{"role": "assistant", "content": f.content},
			}},
		})
	})
}

// TestProviderFactory validates provider selection and configuration errors.
func TestProviderFactory(t *testing.T) {
	if _, err := NewProvider(config.AIAnalyst{Provider: "openai-compatible"}); err == nil {
		t.Error("missing endpoint must error")
	}
	if _, err := NewProvider(config.AIAnalyst{Provider: "openai-compatible", Endpoint: "http://x"}); err == nil {
		t.Error("missing model must error")
	}
	if _, err := NewProvider(config.AIAnalyst{Provider: "weird-llm", Endpoint: "http://x", Model: "m"}); err == nil {
		t.Error("unknown provider must error")
	}

	p, err := NewProvider(config.AIAnalyst{Provider: "openai-compatible", Endpoint: "http://x/v1", Model: "m"})
	if err != nil || p.Name() != "openai-compatible" {
		t.Errorf("openai-compatible: %v %v", p, err)
	}
	p, err = NewProvider(config.AIAnalyst{Provider: "ollama", Endpoint: "http://10.0.0.5:11434", Model: "m"})
	if err != nil || p.Name() != "ollama" {
		t.Errorf("ollama: %v %v", p, err)
	}
	if p.(*openAIProvider).base != "http://10.0.0.5:11434/v1" {
		t.Errorf("ollama endpoint not normalized: %q", p.(*openAIProvider).base)
	}
	p, err = NewProvider(config.AIAnalyst{Provider: "opencode", Endpoint: "http://127.0.0.1:4096", Model: "opencode/m"})
	if err != nil || p.Name() != "opencode" {
		t.Errorf("opencode: %v %v", p, err)
	}
}

func TestOpenAIServiceSuccess(t *testing.T) {
	fake := newFakeOpenAI(t, `{"title":"ok"}`)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	p, err := NewProvider(config.AIAnalyst{
		Provider: "openai-compatible",
		Endpoint: srv.URL,
		APIKey:   "k-123",
		Model:    "test-model",
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.Analyze(context.Background(), Request{System: "s", Prompt: "p", Model: "test-model", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if out != `{"title":"ok"}` {
		t.Errorf("content: %q", out)
	}
	if auth, _ := fake.lastAuth.Load().(string); auth != "Bearer k-123" {
		t.Errorf("auth header: %q", auth)
	}
	body, _ := fake.lastBody.Load().(string)
	if !strings.Contains(body, "test-model") {
		t.Errorf("model not in request body: %s", body)
	}
}

func TestOpenAIServiceAuthFailure(t *testing.T) {
	fake := newFakeOpenAI(t, "")
	fake.key = "the-right-key"
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	p, _ := NewProvider(config.AIAnalyst{Provider: "openai-compatible", Endpoint: srv.URL, APIKey: "wrong", Model: "m"})
	_, err := p.Analyze(context.Background(), Request{Prompt: "x", Model: "m", Timeout: 5 * time.Second})
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
	if strings.Contains(err.Error(), "the-right-key") {
		t.Error("error message leaked the expected API key")
	}
}

func TestOpenAIServiceRateLimit(t *testing.T) {
	fake := newFakeOpenAI(t, "")
	fake.status = 429
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	p, _ := NewProvider(config.AIAnalyst{Provider: "openai-compatible", Endpoint: srv.URL, Model: "m"})
	_, err := p.Analyze(context.Background(), Request{Prompt: "x", Model: "m", Timeout: 5 * time.Second})
	if !errors.Is(err, ErrRateLimited) || !IsTransient(err) {
		t.Fatalf("want transient ErrRateLimited, got %v", err)
	}
}

func TestOpenAIServiceServerErrorUnavailable(t *testing.T) {
	fake := newFakeOpenAI(t, "")
	fake.status = 503
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	p, _ := NewProvider(config.AIAnalyst{Provider: "openai-compatible", Endpoint: srv.URL, Model: "m"})
	_, err := p.Analyze(context.Background(), Request{Prompt: "x", Model: "m", Timeout: 5 * time.Second})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

func TestOpenAIServiceTimeout(t *testing.T) {
	fake := newFakeOpenAI(t, "")
	fake.latency = 300 * time.Millisecond
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	p, _ := NewProvider(config.AIAnalyst{Provider: "openai-compatible", Endpoint: srv.URL, Model: "m"})
	_, err := p.Analyze(context.Background(), Request{Prompt: "x", Model: "m", Timeout: 50 * time.Millisecond})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("want ErrTimeout, got %v", err)
	}
}

func TestOpenAIServiceUnavailableEndpoint(t *testing.T) {
	p, _ := NewProvider(config.AIAnalyst{Provider: "openai-compatible", Endpoint: "http://127.0.0.1:1", Model: "m"})
	_, err := p.Analyze(context.Background(), Request{Prompt: "x", Model: "m", Timeout: 2 * time.Second})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

func TestOpenAIServiceMalformedResponse(t *testing.T) {
	fake := newFakeOpenAI(t, "")
	fake.rawResponse = `<html>gateway error</html>`
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	p, _ := NewProvider(config.AIAnalyst{Provider: "openai-compatible", Endpoint: srv.URL, Model: "m"})
	_, err := p.Analyze(context.Background(), Request{Prompt: "x", Model: "m", Timeout: 5 * time.Second})
	if !errors.Is(err, ErrBadResponse) {
		t.Fatalf("want ErrBadResponse, got %v", err)
	}
}

func TestOpenAIHealth(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/models" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":[{"id":"qwen3.8"},{"id":"gpt-5"}]}`)
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	p, _ := NewProvider(config.AIAnalyst{Provider: "openai-compatible", Endpoint: srv.URL, Model: "qwen3.8"})
	health, err := p.Health(context.Background())
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	if !health.OK {
		t.Error("health not ok")
	}
	if health.Model == "" {
		t.Error("no model reported")
	}
	ids, ok, err := p.Models(context.Background())
	if err != nil || !ok || len(ids) != 2 {
		t.Errorf("models: %v %v %v", ids, ok, err)
	}
}

func TestOpenAIHealthAuthFailure(t *testing.T) {
	fake := newFakeOpenAI(t, "")
	fake.key = "the-right-key"
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	p, _ := NewProvider(config.AIAnalyst{Provider: "openai-compatible", Endpoint: srv.URL, Model: "m"})
	health, err := p.Health(context.Background())
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
	if health.OK {
		t.Error("health must not be ok on auth failure")
	}
}

// ─────────────────────────────────────────────
// OpenCode provider
// ─────────────────────────────────────────────

type fakeOpenCode struct {
	t          *testing.T
	authUser   string
	authPass   string
	sessionIDs int64
	calls      []string
	lastTools  atomic.Value
}

func newFakeOpenCode(t *testing.T) *fakeOpenCode {
	return &fakeOpenCode{t: t, authUser: "opencode", authPass: "pw"}
}

func (f *fakeOpenCode) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		if f.authPass != "" {
			user, pass, ok := r.BasicAuth()
			if !ok || user != f.authUser || pass != f.authPass {
				w.Header().Set("WWW-Authenticate", `Basic realm="opencode"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/global/health":
			fmt.Fprint(w, `{"healthy":true,"version":"1.18.20"}`)
		case r.URL.Path == "/experimental/tool/ids":
			fmt.Fprint(w, `["bash","read","write","webfetch"]`)
		case r.URL.Path == "/config/providers":
			fmt.Fprint(w, `{"providers":[{"id":"opencode","name":"OpenCode","models":{"qwen3.8":{"name":"Qwen 3.8"}}}],"default":{}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/session":
			fmt.Fprint(w, `{"id":"ses_test_1"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/session/ses_test_1/message":
			var body struct {
				Parts  []map[string]any `json:"parts"`
				System string           `json:"system"`
				Model  *struct {
					ProviderID string `json:"providerID"`
					ModelID    string `json:"modelID"`
				} `json:"model"`
				Tools map[string]bool `json:"tools"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Model == nil || body.Model.ProviderID != "opencode" || body.Model.ModelID != "qwen3.8" {
				http.Error(w, `{"error":{"name":"UnknownError","data":{"message":"bad model"}}}`, http.StatusBadRequest)
				return
			}
			if body.System == "" || len(body.Parts) == 0 {
				http.Error(w, `{"error":{"name":"UnknownError","data":{"message":"missing prompt"}}}`, http.StatusBadRequest)
				return
			}
			if f.lastTools.Load() == nil {
				f.lastTools.Store(body.Tools)
			}
			fmt.Fprint(w, `{"info":{"role":"assistant"},"parts":[{"type":"text","text":"opencode says ok","synthetic":false,"ignored":false}]}`)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/session/"):
			fmt.Fprint(w, `true`)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})
}

func TestOpenCodeProviderAnalyze(t *testing.T) {
	fake := newFakeOpenCode(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	p, err := NewProvider(config.AIAnalyst{
		Provider: "opencode",
		Endpoint: srv.URL,
		APIKey:   "pw",
		Model:    "opencode/qwen3.8",
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.Analyze(context.Background(), Request{System: "sys", Prompt: "prompt", Model: "opencode/qwen3.8", Timeout: 5 * time.Second, NoTools: true})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if out != "opencode says ok" {
		t.Errorf("content: %q", out)
	}
	// The session must be cleaned up.
	deleted := false
	for _, c := range fake.calls {
		if c == "DELETE /session/ses_test_1" {
			deleted = true
		}
	}
	if !deleted {
		t.Errorf("session not deleted: %v", fake.calls)
	}
	// Tools must be disabled when NoTools is set.
	if tools, _ := fake.lastTools.Load().(map[string]bool); tools == nil {
		t.Error("tools map not sent")
	} else {
		for name, enabled := range tools {
			if enabled {
				t.Errorf("tool %q not disabled", name)
			}
		}
	}
}

func TestOpenCodeProviderBadModelRef(t *testing.T) {
	fake := newFakeOpenCode(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	p, _ := NewProvider(config.AIAnalyst{Provider: "opencode", Endpoint: srv.URL, APIKey: "pw", Model: "qwen3.8"})
	_, err := p.Analyze(context.Background(), Request{Prompt: "x", Timeout: 2 * time.Second})
	if !errors.Is(err, ErrBadConfig) {
		t.Fatalf("want ErrBadConfig for bare model, got %v", err)
	}
}

func TestOpenCodeProviderAuthFailure(t *testing.T) {
	fake := newFakeOpenCode(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	p, _ := NewProvider(config.AIAnalyst{Provider: "opencode", Endpoint: srv.URL, APIKey: "wrong", Model: "opencode/qwen3.8"})
	_, err := p.Analyze(context.Background(), Request{Prompt: "x", Timeout: 2 * time.Second})
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
}

func TestOpenCodeProviderHealth(t *testing.T) {
	fake := newFakeOpenCode(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	p, _ := NewProvider(config.AIAnalyst{Provider: "opencode", Endpoint: srv.URL, APIKey: "pw", Model: "opencode/qwen3.8"})
	health, err := p.Health(context.Background())
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	if !health.OK || !strings.Contains(health.Detail, "1.18.20") {
		t.Errorf("health: %+v", health)
	}
	ids, ok, err := p.Models(context.Background())
	if err != nil || !ok || len(ids) != 1 || ids[0] != "opencode/qwen3.8" {
		t.Errorf("models: %v %v %v", ids, ok, err)
	}
}

func TestOpenCodeProviderModelError(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/session":
			fmt.Fprint(w, `{"id":"ses_x"}`)
		case strings.Contains(r.URL.Path, "/message"):
			fmt.Fprint(w, `{"info":{"role":"assistant","error":{"name":"ProviderAuthError","data":{"providerID":"opencode","message":"bad zen key"}}},"parts":[]}`)
		default:
			fmt.Fprint(w, `true`)
		}
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	p, _ := NewProvider(config.AIAnalyst{Provider: "opencode", Endpoint: srv.URL, Model: "opencode/qwen3.8"})
	_, err := p.Analyze(context.Background(), Request{Prompt: "x", Timeout: 2 * time.Second})
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
	if !strings.Contains(err.Error(), "bad zen key") {
		t.Errorf("error detail lost: %v", err)
	}
}
