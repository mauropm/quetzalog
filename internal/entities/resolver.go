package entities

import (
	"context"
	"strings"
	"time"

	"quetzalog/internal/correlation"
	"quetzalog/pkg/event"
)

// Resolver applies v2 entity extraction and provenance to the write path.
// It wraps the hot 5-tuple graph (internal/correlation) and the v2 store.
// All work is synchronous, bounded, and cheap: one alias probe plus
// relationship-meta upserts per event.
type Resolver struct {
	Graph *correlation.Graph
	Store *Store
}

// NewResolver creates a write-path resolver.
func NewResolver(g *correlation.Graph, s *Store) *Resolver {
	return &Resolver{Graph: g, Store: s}
}

// FromEvent extracts v2 entity candidates from an event, upserts them into
// the hot graph, records observed relationship provenance, and probes
// host/ip co-occurrence for alias candidates (probable, not confirmed).
func (r *Resolver) FromEvent(ctx context.Context, ev *event.Event) {
	if r == nil || ev == nil {
		return
	}
	now := time.Now().UTC()

	// v2 extraction from attributes (domain/url/email/hash/file/process/user).
	for _, ex := range ExtractFromAttributes(ev.Attributes) {
		_ = r.Graph.UpsertEntity(ctx, &correlation.Entity{
			Type:      correlation.EntityType(ex.Type),
			Value:     ex.Value,
			FirstSeen: now,
			LastSeen:  now,
			Count:     1,
		})
		// Original pre-normalization forms are exact aliases.
		for _, alias := range ex.Aliases {
			_ = r.Store.UpsertIdentity(ctx, Identity{
				CanonicalType:  ex.Type,
				CanonicalValue: ex.Value,
				AliasType:      ex.Type,
				AliasValue:     alias,
				Status:         "confirmed",
				Confidence:     1.0,
				Source:         "observation",
			})
		}
	}

	// Host/ip co-occurrence: candidate alias, probable by design —
	// confirmation requires DNS/SMB evidence or an analyst link.
	if ev.Host != "" {
		if ev.SourceIP != "" {
			_ = r.Store.UpsertIdentity(ctx, Identity{
				CanonicalType: "host", CanonicalValue: ev.Host,
				AliasType: "ip", AliasValue: ev.SourceIP,
				Status: "probable", Confidence: 0.8, Source: "observation",
			})
		}
		if ev.DestinationIP != "" {
			_ = r.Store.UpsertIdentity(ctx, Identity{
				CanonicalType: "host", CanonicalValue: ev.Host,
				AliasType: "ip", AliasValue: ev.DestinationIP,
				Status: "probable", Confidence: 0.8, Source: "observation",
			})
		}
	}

	// Observed edge provenance (the hot edges themselves are written by
	// correlation.Graph.AddEntityFromEvent in the events store). Deny/block
	// outcomes keep their edges in the distinct "blocked" state so
	// attempted activity is never rendered as successful.
	blocked := isBlockedOutcome(ev.Outcome)
	upsertEdge := func(fromType, from, toType, to, relation, state string) {
		if from == "" || to == "" {
			return
		}
		_ = r.Store.UpsertRelationshipMeta(ctx, RelationshipMeta{
			FromType: fromType, FromValue: from,
			ToType: toType, ToValue: to,
			Relation: relation,
			Status:     state,
			SourceType: "event",
			SourceID:   ev.ID,
			LastSeen:   now,
		})
	}
	upsertEdge("ip", ev.SourceIP, "ip", ev.DestinationIP, "connected_to", edgeState("observed", blocked))
	upsertEdge("user", ev.User, "host", ev.Host, "auth_from", edgeState("observed", blocked))
	upsertEdge("host", ev.Host, "process", ev.Process, "executed", "observed")
	upsertEdge("host", ev.Host, "file", ev.FilePath, "accessed", "observed")
}

func edgeState(normal string, blocked bool) string {
	if blocked {
		return "blocked"
	}
	return normal
}

// isBlockedOutcome recognizes deny/block outcome spellings.
func isBlockedOutcome(o string) bool {
	switch strings.ToLower(strings.TrimSpace(o)) {
	case "deny", "denied", "block", "blocked", "failure", "failed", "fail":
		return true
	}
	return false
}
