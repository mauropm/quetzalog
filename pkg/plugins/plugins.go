package plugins

import (
	"context"
	"sync"

	"quetzalog/pkg/event"
)

// Ingestor defines the interface for components that ingest events
// from external sources (e.g., log files, network streams, APIs).
type Ingestor interface {
	// Name returns the unique identifier for this ingestor.
	Name() string

	// Start begins the ingestor's data collection loop. It should be
	// non-blocking and return an error if initialization fails.
	Start(ctx context.Context) error

	// Stop gracefully terminates the ingestor. It should block until
	// all in-flight operations are complete or ctx is cancelled.
	Stop(ctx context.Context) error

	// IsRunning returns true if the ingestor is currently active.
	IsRunning() bool
}

// Enricher defines the interface for components that augment events
// with additional context (e.g., geolocation, asset metadata, threat intel).
type Enricher interface {
	// Name returns the unique identifier for this enricher.
	Name() string

	// Enrich modifies the given event in place by adding or updating
	// fields based on external data sources. Returns an error if the
	// enrichment process fails entirely; partial failures should be
	// logged and non-fatal fields left unchanged.
	Enrich(ctx context.Context, e *event.Event) error
}

// Analyzer defines the interface for components that analyze events
// to detect patterns, anomalies, or security threats.
type Analyzer interface {
	// Name returns the unique identifier for this analyzer.
	Name() string

	// Analyze processes a batch of events and returns analysis results.
	// The input events, context, and optional prompt guide the analysis.
	// Returns structured findings, recommendations, and a confidence score.
	Analyze(ctx context.Context, input AnalysisInput) (AnalysisResult, error)
}

// AnalysisInput contains the data passed to an Analyzer.
type AnalysisInput struct {
	// Events is the batch of events to analyze.
	Events []*event.Event

	// Context provides additional metadata or session state for the analysis.
	// Keys may include "user_id", "correlation_id", "environment", etc.
	Context map[string]any

	// Prompt is an optional human-readable instruction or filter for the analysis.
	// For example: "Detect unauthorized access attempts in the last 24 hours".
	Prompt string
}

// AnalysisResult contains the output from an Analyzer.
type AnalysisResult struct {
	// Summary is a human-readable overview of the analysis findings.
	Summary string

	// Findings is a list of specific observations or detected events.
	Findings []string

	// Recommendations is a list of suggested actions based on the findings.
	Recommendations []string

	// Confidence is a value between 0.0 and 1.0 representing the
	// confidence level of the analysis.
	Confidence float64
}

// Plugin is a composite interface combining all plugin types.
// A plugin implementing this interface can serve as an ingestor,
// enricher, and analyzer simultaneously.
type Plugin interface {
	Ingestor
	Enricher
	Analyzer
}

// PluginRegistry manages the lifecycle of registered plugins.
type PluginRegistry struct {
	mu        sync.Mutex
	ingestors map[string]Ingestor
	enrichers map[string]Enricher
	analyzers map[string]Analyzer
}

// NewPluginRegistry creates an empty plugin registry.
func NewPluginRegistry() *PluginRegistry {
	return &PluginRegistry{
		ingestors: make(map[string]Ingestor),
		enrichers: make(map[string]Enricher),
		analyzers: make(map[string]Analyzer),
	}
}

// RegisterIngestor registers an ingestor by name. Returns error if already registered.
func (r *PluginRegistry) RegisterIngestor(i Ingestor) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.ingestors[i.Name()]; exists {
		return &PluginError{Plugin: i.Name(), Type: "ingestor", Action: "register", Reason: "already registered"}
	}

	r.ingestors[i.Name()] = i
	return nil
}

// RegisterEnricher registers an enricher by name. Returns error if already registered.
func (r *PluginRegistry) RegisterEnricher(e Enricher) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.enrichers[e.Name()]; exists {
		return &PluginError{Plugin: e.Name(), Type: "enricher", Action: "register", Reason: "already registered"}
	}

	r.enrichers[e.Name()] = e
	return nil
}

// RegisterAnalyzer registers an analyzer by name. Returns error if already registered.
func (r *PluginRegistry) RegisterAnalyzer(a Analyzer) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.analyzers[a.Name()]; exists {
		return &PluginError{Plugin: a.Name(), Type: "analyzer", Action: "register", Reason: "already registered"}
	}

	r.analyzers[a.Name()] = a
	return nil
}

// GetIngestor returns an ingestor by name.
func (r *PluginRegistry) GetIngestor(name string) (Ingestor, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	i, ok := r.ingestors[name]
	return i, ok
}

// GetEnricher returns an enricher by name.
func (r *PluginRegistry) GetEnricher(name string) (Enricher, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	e, ok := r.enrichers[name]
	return e, ok
}

// GetAnalyzer returns an analyzer by name.
func (r *PluginRegistry) GetAnalyzer(name string) (Analyzer, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	a, ok := r.analyzers[name]
	return a, ok
}

// StartAll starts all registered ingestors. Returns on the first error encountered.
func (r *PluginRegistry) StartAll(ctx context.Context) error {
	r.mu.Lock()
	ingestors := make([]Ingestor, 0, len(r.ingestors))
	for _, i := range r.ingestors {
		ingestors = append(ingestors, i)
	}
	r.mu.Unlock()

	for _, i := range ingestors {
		if err := i.Start(ctx); err != nil {
			return &PluginError{Plugin: i.Name(), Type: "ingestor", Action: "start", Reason: err.Error()}
		}
	}
	return nil
}

// StopAll stops all registered ingestors gracefully. Errors are logged but do not
// stop the shutdown of remaining ingestors.
func (r *PluginRegistry) StopAll(ctx context.Context) {
	r.mu.Lock()
	ingestors := make([]Ingestor, 0, len(r.ingestors))
	for _, i := range r.ingestors {
		ingestors = append(ingestors, i)
	}
	r.mu.Unlock()

	for _, i := range ingestors {
		if err := i.Stop(ctx); err != nil {
			// Note: In production code, this would log via slog.
			// The logging import is available in the api package; here we omit to keep plugins minimal.
			_ = err
		}
	}
}

// RunEnrichers executes the Enrich method on all registered enrichers for a given event.
// Returns a list of errors encountered; the event may be partially enriched.
func (r *PluginRegistry) RunEnrichers(ctx context.Context, e *event.Event) []error {
	r.mu.Lock()
	enrichers := make([]Enricher, 0, len(r.enrichers))
	for _, en := range r.enrichers {
		enrichers = append(enrichers, en)
	}
	r.mu.Unlock()

	var errs []error
	for _, en := range enrichers {
		if err := en.Enrich(ctx, e); err != nil {
			errs = append(errs, &PluginError{Plugin: en.Name(), Type: "enricher", Action: "enrich", Reason: err.Error()})
		}
	}
	return errs
}

// RunAnalyzers executes the Analyze method on all registered analyzers.
// Returns a list of results (one per analyzer) and errors.
func (r *PluginRegistry) RunAnalyzers(ctx context.Context, input AnalysisInput) ([]AnalysisResult, []error) {
	r.mu.Lock()
	analyzers := make([]Analyzer, 0, len(r.analyzers))
	for _, a := range r.analyzers {
		analyzers = append(analyzers, a)
	}
	r.mu.Unlock()

	var (
		results []AnalysisResult
		errs    []error
	)

	for _, a := range analyzers {
		res, err := a.Analyze(ctx, input)
		if err != nil {
			errs = append(errs, &PluginError{Plugin: a.Name(), Type: "analyzer", Action: "analyze", Reason: err.Error()})
			continue
		}
		results = append(results, res)
	}
	return results, errs
}

// PluginError represents an error originating from a plugin operation.
type PluginError struct {
	Plugin string
	Type   string
	Action string
	Reason string
}

func (e *PluginError) Error() string {
	return "plugin error [" + e.Type + "] " + e.Plugin + ": " + e.Action + " failed — " + e.Reason
}
