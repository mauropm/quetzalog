package threatintel

import (
	"context"
	"fmt"
	"sync"
)

// Provider is a source of indicators. Sync must be offline-safe: network
// failures yield an error (never partial state), and results are validated
// before touching the store (external TI is untrusted input).
type Provider interface {
	Name() string
	Sync(ctx context.Context) ([]InIndicator, error)
}

// InternalProvider serves the built-in indicator store: analyst-created
// indicators are themselves a (first-party) feed.
type InternalProvider struct {
	store *Store
}

// NewInternalProvider creates the internal feed provider.
func NewInternalProvider(store *Store) *InternalProvider {
	return &InternalProvider{store: store}
}

// Name returns the provider name.
func (p *InternalProvider) Name() string { return "internal" }

// Sync lists the currently stored indicators. It is a read-only pass: the
// store is the source of truth, so nothing is re-written.
func (p *InternalProvider) Sync(ctx context.Context) ([]InIndicator, error) {
	list, _, err := p.store.List(ctx, ListFilter{Limit: 500})
	if err != nil {
		return nil, err
	}
	out := make([]InIndicator, 0, len(list))
	for _, i := range list {
		out = append(out, InIndicator{
			Type:        i.Type,
			Value:       i.Value,
			Severity:    i.Severity,
			Description: i.Description,
			Source:      i.Source,
			Confidence:  i.Confidence,
		})
	}
	return out, nil
}

// Registry holds the active providers and their sync state.
type Registry struct {
	mu         sync.RWMutex
	providers  map[string]Provider
	order      []string
	store      *Store
}

// NewRegistry creates an empty registry over the given store.
func NewRegistry(store *Store) *Registry {
	return &Registry{providers: map[string]Provider{}, store: store}
}

// Register adds a provider (replacing any provider of the same name).
func (r *Registry) Register(p Provider) {
	if p == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.providers[p.Name()]; !ok {
		r.order = append(r.order, p.Name())
	}
	r.providers[p.Name()] = p
}

// Provider returns a registered provider.
func (r *Registry) Provider(name string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	return p, ok
}

// Store exposes the backing indicator store.
func (r *Registry) Store() *Store { return r.store }

// Names lists the registered provider names in registration order.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, len(r.order))
	copy(out, r.order)
	return out
}

// Sync runs one provider, imports its indicators and records the state.
func (r *Registry) Sync(ctx context.Context, name string) (int, error) {
	p, ok := r.Provider(name)
	if !ok {
		return 0, fmt.Errorf("unknown provider %q", name)
	}
	inds, err := p.Sync(ctx)
	if err != nil {
		_ = r.store.SetProviderState(ctx, ProviderState{
			Provider:   name,
			LastStatus: "error",
			LastError:  err.Error(),
		})
		return 0, fmt.Errorf("sync provider %s: %w", name, err)
	}
	var imported int
	for _, in := range inds {
		if in.Source == "" {
			in.Source = name
		}
		if in.Type == "" || in.Value == "" {
			continue
		}
		if _, err := r.store.Upsert(ctx, in); err != nil {
			// A single bad item must not poison the whole feed:
			// validate-and-skip (external TI is untrusted input).
			continue
		}
		imported++
	}
	_ = r.store.SetProviderState(ctx, ProviderState{
		Provider:       name,
		LastStatus:     "ok",
		LastError:      "",
		IndicatorCount: imported,
	})
	return imported, nil
}

// SyncAll runs every registered provider; per-provider errors are
// collected, never fatal.
func (r *Registry) SyncAll(ctx context.Context) (int, []string) {
	total := 0
	var errs []string
	for _, name := range r.Names() {
		n, err := r.Sync(ctx, name)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		total += n
	}
	return total, errs
}
