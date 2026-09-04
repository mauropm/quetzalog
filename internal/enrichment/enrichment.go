package enrichment

import (
	"context"
	"quetzalog/pkg/event"
)

// Enricher is the interface for event enrichment.
type Enricher interface {
	Name() string
	Enrich(ctx context.Context, event *event.Event) error
}

// LocalIPEnricher adds descriptions to known IPs.
type LocalIPEnricher struct {
	knownIPs map[string]string // IP -> description
}

// NewLocalIPEnricher creates a new LocalIPEnricher.
func NewLocalIPEnricher() *LocalIPEnricher {
	return &LocalIPEnricher{
		knownIPs: make(map[string]string),
	}
}

// Name returns the name of the enricher.
func (e *LocalIPEnricher) Name() string {
	return "local_ip"
}

// AddIP adds a known IP with its description.
func (e *LocalIPEnricher) AddIP(ip, description string) {
	e.knownIPs[ip] = description
}

// Enrich adds local IP information to the event.
func (e *LocalIPEnricher) Enrich(ctx context.Context, ev *event.Event) error {
	if ev.SourceIP != "" {
		if desc, ok := e.knownIPs[ev.SourceIP]; ok {
			if ev.Attributes == nil {
				ev.Attributes = make(map[string]any)
			}
			ev.Attributes["source_ip_description"] = desc
		}
	}

	if ev.DestinationIP != "" {
		if desc, ok := e.knownIPs[ev.DestinationIP]; ok {
			if ev.Attributes == nil {
				ev.Attributes = make(map[string]any)
			}
			ev.Attributes["destination_ip_description"] = desc
		}
	}

	return nil
}

// BuildGeoIPEnricher creates a GeoIP enricher from config, replacing the old stub.
func BuildGeoIPEnricher(cfg GeoIPConfig) (*GeoIPEnricher, error) {
	return NewGeoIPEnricher(cfg)
}

// CompositeEnricher chains multiple enrichers together.
type CompositeEnricher struct {
	enrichers []Enricher
}

// NewCompositeEnricher creates a new CompositeEnricher with the given enrichers.
func NewCompositeEnricher(enrichers []Enricher) *CompositeEnricher {
	return &CompositeEnricher{
		enrichers: enrichers,
	}
}

// Enrich runs all enrichers in order.
func (e *CompositeEnricher) Enrich(ctx context.Context, ev *event.Event) error {
	for _, enricher := range e.enrichers {
		if err := enricher.Enrich(ctx, ev); err != nil {
			return err
		}
	}
	return nil
}
