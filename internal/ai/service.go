package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"quetzalog/internal/config"
	"quetzalog/internal/findings"
)

// Sentinel errors returned by the service for operator-facing failures.
var (
	ErrDisabled      = errors.New("AI analyst is disabled")
	ErrInProgress    = errors.New("an analysis for this finding is already in progress")
	ErrBelowSeverity = errors.New("finding severity is below the analysis threshold")
	ErrNoFinding     = errors.New("finding not found")
	ErrNoAnalysis    = errors.New("no completed analysis to decide")
	ErrInvalidConfig = errors.New("invalid AI analyst configuration")
)

// severityRank orders the SOC scale for threshold comparisons.
func severityRank(sev string) int {
	switch findings.Severity(sev) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

// Service orchestrates the analyst pipeline: context building, prompting,
// provider calls, validation, persistence and human decisions. It never
// executes recommended actions.
type Service struct {
	cfg     *config.Config // live configuration (shared with the API layer)
	cfgPath string         // config file to persist changes to ("" = memory only)

	store       *Store
	findings    *findings.Store
	builder     *ContextBuilder
	providerFor func(cfg config.AIAnalyst) (Provider, error)
	logger      *slog.Logger

	limiterMu sync.Mutex
	limiter   *tokenBucket
	limiterRP float64 // rate the limiter was built for
}

// NewService wires the analyst service. providerFor may be nil to use the
// default provider factory (used by tests to inject fakes).
func NewService(cfg *config.Config, cfgPath string, store *Store, findingStore *findings.Store, builder *ContextBuilder, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		cfg:         cfg,
		cfgPath:     cfgPath,
		store:       store,
		findings:    findingStore,
		builder:     builder,
		providerFor: NewProvider,
		logger:      logger,
	}
}

// SetProviderFor swaps the provider factory (tests).
func (s *Service) SetProviderFor(fn func(cfg config.AIAnalyst) (Provider, error)) {
	if fn != nil {
		s.providerFor = fn
	}
}

func (s *Service) aiConfig() config.AIAnalyst { return s.cfg.AIAnalyst }

// Config returns the current live AI configuration.
func (s *Service) Config() config.AIAnalyst { return s.cfg.AIAnalyst }

// Persisted reports whether configuration changes are written to a file.
func (s *Service) Persisted() bool { return s.cfgPath != "" }

// AIAnalystView is the wire shape used by the settings API. APIKey semantics:
// empty string keeps the existing key; "$CLEAR" removes it; anything else
// sets a new key.
type AIAnalystView struct {
	Enabled              bool   `json:"enabled"`
	Provider             string `json:"provider"`
	Endpoint             string `json:"endpoint"`
	APIKey               string `json:"api_key"`
	Username             string `json:"username"`
	Model                string `json:"model"`
	MinimumSeverity      string `json:"minimum_severity"`
	MaxRequestsPerMinute int    `json:"max_requests_per_minute"`
	TimeoutSeconds       int    `json:"timeout_seconds"`
	MaxContextEvents     int    `json:"max_context_events"`
	RetryCount           int    `json:"retry_count"`
}

// ToConfig merges the view onto the current configuration (key handling as
// documented on AIAnalystView). ModelRoles and ActionMappings are carried
// over from the current configuration — they are file-managed.
func (v AIAnalystView) ToConfig(current config.AIAnalyst) config.AIAnalyst {
	out := config.AIAnalyst{
		Enabled:              v.Enabled,
		Provider:             v.Provider,
		Endpoint:             v.Endpoint,
		APIKey:               current.APIKey,
		Username:             v.Username,
		Model:                v.Model,
		MinimumSeverity:      v.MinimumSeverity,
		MaxRequestsPerMinute: v.MaxRequestsPerMinute,
		TimeoutSeconds:       v.TimeoutSeconds,
		MaxContextEvents:     v.MaxContextEvents,
		RetryCount:           v.RetryCount,
		ModelRoles:           current.ModelRoles,
		ActionMappings:       current.ActionMappings,
	}
	if v.APIKey == "$CLEAR" {
		out.APIKey = ""
	} else if v.APIKey != "" {
		out.APIKey = v.APIKey
	}
	return out
}

// UpdateConfig validates and applies a new AIAnalyst configuration. The
// shared config is updated in place; when a config file is in use the change
// is persisted there. ModelRoles and ActionMappings are preserved from the
// current configuration (file-managed, not part of the settings view).
func (s *Service) UpdateConfig(ctx context.Context, in config.AIAnalyst) error {
	if err := validateAIConfig(in); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	// Sensible floors so a bad value cannot wedge the service.
	if in.MaxRequestsPerMinute <= 0 {
		in.MaxRequestsPerMinute = 10
	}
	if in.TimeoutSeconds <= 0 {
		// Local models are slow; 300s is the floor for one analyst call.
		in.TimeoutSeconds = 300
	}
	if in.MaxContextEvents <= 0 {
		in.MaxContextEvents = 100
	}
	if in.RetryCount < 0 {
		in.RetryCount = 0
	}
	if in.RetryCount > 5 {
		in.RetryCount = 5
	}
	if in.MinimumSeverity == "" {
		in.MinimumSeverity = "medium"
	}
	in.Provider = normalizeProvider(in.Provider)
	in.Endpoint = strings.TrimSpace(in.Endpoint)

	s.cfg.AIAnalyst = in
	if s.cfgPath != "" {
		// Preserve the operator's other sections and comments in the file.
		if err := s.cfg.SaveAIAnalyst(s.cfgPath); err != nil {
			return fmt.Errorf("configuration applied but not persisted: %w", err)
		}
	}
	s.logger.Info("ai analyst configuration updated",
		"provider", in.Provider, "endpoint", in.Endpoint, "model", in.Model, "enabled", in.Enabled)
	return nil
}

func normalizeProvider(p string) string {
	switch p {
	case "openai", "openai_compatible":
		return "openai-compatible"
	case "":
		return "openai-compatible"
	}
	return p
}

func validateAIConfig(in config.AIAnalyst) error {
	p := normalizeProvider(in.Provider)
	switch p {
	case "openai-compatible", "ollama", "opencode":
	default:
		return fmt.Errorf("provider must be openai-compatible, ollama or opencode (got %q)", in.Provider)
	}
	if in.Endpoint == "" {
		return errors.New("endpoint is required")
	}
	// The model is only required when something will actually run with it:
	// automatic analysis on, or — enforced at use-time in NewProvider — a
	// manual analysis. Saving an endpoint without a model is valid because
	// the model-listing flow exists to discover the model name.
	if in.Model == "" && in.Enabled {
		return errors.New("model is required when automatic analysis is enabled")
	}
	if in.MinimumSeverity != "" && !contains([]string{"critical", "high", "medium", "low"}, in.MinimumSeverity) {
		return fmt.Errorf("minimum_severity must be critical, high, medium or low (got %q)", in.MinimumSeverity)
	}
	return nil
}

// AnalyzeFinding runs the full pipeline for one finding and stores the
// result. manual=true (explicit operator request) bypasses the enabled flag,
// the severity floor and the "already analyzed" guard. instruction is the
// optional analyst guidance text (layered below the system policy).
func (s *Service) AnalyzeFinding(ctx context.Context, findingID, instruction string, manual bool) (*Row, error) {
	cfg := s.aiConfig()

	f, err := s.findings.GetByID(ctx, findingID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrNoFinding, findingID)
	}

	if !manual {
		if !cfg.Enabled {
			return nil, ErrDisabled
		}
		if severityRank(f.Severity) < severityRank(cfg.MinimumSeverity) {
			return nil, fmt.Errorf("%w: finding is %s, minimum is %s", ErrBelowSeverity, f.Severity, cfg.MinimumSeverity)
		}
	}

	if existing, err := s.store.ActiveByFinding(ctx, findingID); err == nil && existing != nil {
		switch existing.Status {
		case "analyzing":
			return existing, ErrInProgress
		case "analyzed", "approved", "dismissed":
			if !manual {
				return existing, nil // already analyzed; deduplication
			}
		}
	}

	if !s.allow() {
		return nil, fmt.Errorf("%w: max requests per minute reached — try again shortly", ErrRateLimited)
	}

	// The reasoning role (when configured) handles finding generation and
	// attack-chain analysis; otherwise the main endpoint is used (spec §61).
	roleCfg := s.roleConfig(cfg, "reasoning")
	provider, err := s.providerFor(roleCfg)
	if err != nil {
		return nil, err
	}

	fctx, err := s.builder.Build(ctx, f, cfg.MaxContextEvents)
	if err != nil {
		return nil, fmt.Errorf("build context: %w", err)
	}
	prompt, err := BuildUserPrompt(fctx, instruction)
	if err != nil {
		return nil, err
	}
	ctxJSON, err := marshalContext(fctx)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(ctxJSON))
	contextHash := hex.EncodeToString(sum[:])

	row, err := s.store.CreateOrReset(ctx, CreateArgs{
		FindingID:     f.ID,
		Provider:      provider.Name(),
		Model:         roleCfg.Model,
		ModelVersion:  roleCfg.Model,
		ContextHash:   contextHash,
		PromptVersion: PromptVersion,
		PromptHash:    PromptHash(),
		ContextJSON:   ctxJSON,
	})
	if err != nil {
		return nil, err
	}

	out, aerr := s.runProvider(ctx, provider, roleCfg, prompt)
	if aerr != nil {
		_ = s.store.Fail(ctx, row.ID, aerr.Error())
		s.logger.Warn("ai analysis failed", "finding", f.ID, "analysis", row.ID, "error", aerr)
		if r, gerr := s.store.ActiveByFinding(ctx, findingID); gerr == nil {
			return r, aerr
		}
		return row, aerr
	}

	a, verr := ValidateAnalysisWithContext([]byte(out), fctx)
	if verr != nil {
		_ = s.store.Fail(ctx, row.ID, verr.Error())
		s.logger.Warn("ai analysis rejected (invalid model output)", "finding", f.ID, "analysis", row.ID, "reason", verr.Error())
		if r, gerr := s.store.ActiveByFinding(ctx, findingID); gerr == nil {
			return r, verr
		}
		return row, verr
	}

	if err := s.store.Complete(ctx, row.ID, a); err != nil {
		return nil, err
	}
	s.logger.Info("ai analysis completed", "finding", f.ID, "analysis", row.ID,
		"severity", a.Severity, "confidence", a.Confidence,
		"recommended_action", a.RecommendedAction.Type, "model", roleCfg.Model,
		"context_hash", contextHash[:12])
	return s.store.ActiveByFinding(ctx, findingID)
}

// roleConfig returns the effective provider configuration for one model
// role: the role's endpoint/model when configured, falling back to the main
// endpoint/model otherwise. Credentials come from the main configuration.
func (s *Service) roleConfig(cfg config.AIAnalyst, role string) config.AIAnalyst {
	out := cfg
	switch role {
	case "fast":
		r := cfg.ModelRoles.Fast
		if strings.TrimSpace(r.Endpoint) != "" {
			out.Endpoint = r.Endpoint
		}
		if strings.TrimSpace(r.Model) != "" {
			out.Model = r.Model
		}
	case "reasoning":
		r := cfg.ModelRoles.Reasoning
		if strings.TrimSpace(r.Endpoint) != "" {
			out.Endpoint = r.Endpoint
		}
		if strings.TrimSpace(r.Model) != "" {
			out.Model = r.Model
		}
	case "embedding":
		r := cfg.ModelRoles.Embedding
		if strings.TrimSpace(r.Endpoint) != "" {
			out.Endpoint = r.Endpoint
		}
		if strings.TrimSpace(r.Model) != "" {
			out.Model = r.Model
		}
	}
	return out
}

// runProvider calls the model with retries for transient failures.
func (s *Service) runProvider(ctx context.Context, provider Provider, cfg config.AIAnalyst, prompt string) (string, error) {
	req := Request{
		System:  SystemPrompt,
		Prompt:  prompt,
		Model:   cfg.Model,
		Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second,
		NoTools: provider.Name() == "opencode",
	}
	var lastErr error
	for attempt := 0; attempt <= cfg.RetryCount; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}
		out, err := provider.Analyze(ctx, req)
		if err == nil {
			return out, nil
		}
		lastErr = err
		if !IsTransient(err) {
			break
		}
		s.logger.Warn("ai provider transient failure, retrying", "attempt", attempt+1, "provider", provider.Name(), "error", err)
	}
	return "", lastErr
}

// StartAnalysis validates the request and starts an analysis in the
// background. It returns immediately so the HTTP layer is never blocked by
// model latency; the result is observable via the analysis record
// (status: analyzing -> analyzed | failed). instruction is optional analyst
// guidance, layered below the system policy (spec §64).
func (s *Service) StartAnalysis(ctx context.Context, findingID, instruction string) (*Row, error) {
	f, err := s.findings.GetByID(ctx, findingID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrNoFinding, findingID)
	}
	cfg := s.aiConfig()
	if cfg.Endpoint == "" || cfg.Model == "" {
		return nil, fmt.Errorf("%w: endpoint and model must be configured (Settings → AI Analyst)", ErrBadConfig)
	}
	if existing, err := s.store.ActiveByFinding(ctx, findingID); err == nil && existing != nil && existing.Status == "analyzing" {
		return existing, ErrInProgress
	}
	// Analyst guidance is advisory text, not data; bound it so a long pasted
	// block cannot blow out the prompt budget.
	instruction = strings.TrimSpace(instruction)
	if len(instruction) > 4000 {
		instruction = instruction[:4000]
	}
	go func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if _, err := s.AnalyzeFinding(cctx, f.ID, instruction, true); err != nil {
			s.logger.Warn("ai analysis did not complete", "finding", f.ID, "error", err)
		}
	}()
	return nil, nil
}

// OnFindingCreated is the auto-analysis hook wired into the detection
// engine's finding upsert. It runs asynchronously and swallows errors —
// a failed analysis must never break detection runs.
func (s *Service) OnFindingCreated(ctx context.Context, f *findings.Finding) {
	if f == nil {
		return
	}
	go func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if _, err := s.AnalyzeFinding(cctx, f.ID, "", false); err != nil {
			if errors.Is(err, ErrDisabled) || errors.Is(err, ErrBelowSeverity) || errors.Is(err, ErrInProgress) {
				return // expected skips, not errors
			}
			s.logger.Warn("automatic ai analysis did not complete", "finding", f.ID, "error", err)
		}
	}()
}

// Approve records the human approval of a recommendation.
func (s *Service) Approve(ctx context.Context, analysisID, actor string) (*Row, error) {
	row, err := s.decide(ctx, analysisID, "approve", "", actor)
	if err != nil {
		return nil, err
	}
	s.noteFinding(ctx, row, "AI Analyst recommendation approved by "+actor+": "+row.RecommendationType)
	return s.row(ctx, analysisID)
}

// Dismiss records the human dismissal with an optional reason.
func (s *Service) Dismiss(ctx context.Context, analysisID, reason, actor string) (*Row, error) {
	row, err := s.decide(ctx, analysisID, "dismiss", reason, actor)
	if err != nil {
		return nil, err
	}
	s.noteFinding(ctx, row, "AI Analyst recommendation dismissed by "+actor+": "+row.RecommendationType)
	return s.row(ctx, analysisID)
}

// decide validates the state and records the decision.
func (s *Service) decide(ctx context.Context, analysisID, decision, reason, actor string) (*Row, error) {
	row, _, _, err := s.store.Get(ctx, analysisID)
	if err != nil {
		return nil, err
	}
	if row.Status != "analyzed" {
		return nil, ErrNoAnalysis
	}
	if err := s.store.Decide(ctx, analysisID, decision, reason, actor); err != nil {
		return nil, err
	}
	return row, nil
}

func (s *Service) row(ctx context.Context, analysisID string) (*Row, error) {
	r, _, _, err := s.store.Get(ctx, analysisID)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// defaultActionMappings maps the closed recommended_action vocabulary to
// response-registry keys. Mappings are configuration, not code (spec §33):
// operators can re-point types at new integrations without app changes.
var defaultActionMappings = map[string]string{
	"investigate":        "investigation.create",
	"create_incident":    "incident.create",
	"run_query":          "search.run",
	"collect_evidence":   "finding.annotate",
	"escalate":           "webhook.execute",
	"remediate":          "webhook.execute",
	"block":              "webhook.execute",
	"quarantine":         "webhook.execute",
	"disable_account":    "webhook.execute",
	"rotate_credentials": "webhook.execute",
}

// ActionMapping resolves a recommended action type to a response-registry
// key, preferring operator configuration (ai_analyst.action_mappings) over
// the built-in defaults.
func ActionMapping(cfg config.AIAnalyst, actionType string) string {
	if cfg.ActionMappings != nil {
		if m, ok := cfg.ActionMappings[actionType]; ok && m != "" {
			return m
		}
	}
	if m, ok := defaultActionMappings[actionType]; ok {
		return m
	}
	return "webhook.execute"
}

// noteFinding attaches the decision to the finding as a note (audit link).
func (s *Service) noteFinding(ctx context.Context, row *Row, body string) {
	if row == nil || row.FindingID == "" {
		return
	}
	_ = s.findings.AddNote(ctx, &findings.Note{
		FindingID: row.FindingID,
		Author:    "ai-analyst",
		Content:   body,
	})
}

// probeProvider builds a provider for connection tests and model discovery,
// where the configured model is irrelevant — discovery exists precisely to
// find the model name. A missing model is tolerated; the endpoint is not.
func (s *Service) probeProvider(cfg config.AIAnalyst) (Provider, error) {
	if strings.TrimSpace(cfg.Model) == "" {
		cfg.Model = "probe" // placeholder; Health/Models never send it, except the chat fallback
	}
	return s.providerFor(cfg)
}

// TestConnection probes the configured provider without running an
// analysis. The result never includes credentials.
func (s *Service) TestConnection(ctx context.Context) (Health, error) {
	provider, err := s.probeProvider(s.aiConfig())
	if err != nil {
		return Health{}, err
	}
	return provider.Health(ctx)
}

// ListModels returns model identifiers offered by the configured provider,
// when the provider supports discovery.
func (s *Service) ListModels(ctx context.Context) ([]string, bool, error) {
	provider, err := s.probeProvider(s.aiConfig())
	if err != nil {
		return nil, false, err
	}
	return provider.Models(ctx)
}

func (s *Service) allow() bool {
	cfg := s.aiConfig()
	rate := float64(cfg.MaxRequestsPerMinute)
	if rate <= 0 {
		rate = 10
	}
	s.limiterMu.Lock()
	defer s.limiterMu.Unlock()
	if s.limiter == nil || s.limiterRP != rate {
		s.limiter = newTokenBucket(rate/60.0, rate)
		s.limiterRP = rate
	}
	return s.limiter.Allow()
}

// tokenBucket is a small thread-safe token bucket (per-minute burst).
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

// marshalContext serializes the context for storage.
func marshalContext(c *FindingContext) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
