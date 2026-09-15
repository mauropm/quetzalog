package risk

import (
	"context"
	"fmt"
	"strings"

	"quetzalog/internal/assets"
	"quetzalog/internal/entities"
	"quetzalog/pkg/event"
)

// EventScorer records explainable per-event risk contributions
// (docs/risk-model.md §2). Every point added to an entity's risk is a
// recorded contribution with a reason, so any risk number is reconstructable
// from risk_contributions. Severity ≠ confidence: the severity base is a
// points input to risk, not a likelihood.
type EventScorer struct {
	risk   *EntityRiskStore
	assets *assets.Store
	meta   *entities.Store
}

// NewEventScorer creates the per-event risk scorer. The meta store supplies
// identity privilege; pass nil to skip privilege contributions.
func NewEventScorer(riskStore *EntityRiskStore, assetStore *assets.Store, metaStore *entities.Store) *EventScorer {
	return &EventScorer{risk: riskStore, assets: assetStore, meta: metaStore}
}

// severityBase maps a normalized severity to its points
// (critical 50 / high 35 / medium 20 / low 10, extended to the full scale).
func severityBase(severity string) float64 {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "emergency", "critical":
		return 50
	case "alert":
		return 45
	case "err", "error":
		return 35
	case "warning", "warn":
		return 20
	case "notice":
		return 10
	case "info":
		return 5
	default: // debug, unknown, empty
		return 0
	}
}

// assetPoints returns the asset-criticality points for a host (+10/+6/+3/+1).
func (s *EventScorer) assetPoints(ctx context.Context, host string) (float64, string) {
	if s.assets == nil || host == "" {
		return 0, ""
	}
	a, err := s.assets.GetByEntityRef(ctx, "host:"+host)
	if err != nil || a == nil {
		return 0, ""
	}
	switch a.Criticality {
	case "critical":
		return 10, "critical asset " + a.Name
	case "high":
		return 6, "high-criticality asset " + a.Name
	case "medium":
		return 3, "medium-criticality asset " + a.Name
	case "low":
		return 1, "low-criticality asset " + a.Name
	}
	return 0, ""
}

// userPoints returns the identity-privilege points for a user (+10 admin,
// +5 other privileged).
func (s *EventScorer) userPoints(ctx context.Context, user string) (float64, string) {
	if s.meta == nil || user == "" {
		return 0, ""
	}
	m, err := s.meta.GetMeta(ctx, "user", user)
	if err != nil || m == nil {
		return 0, ""
	}
	switch m.Privilege {
	case "admin":
		return 10, "privileged identity " + user + " (admin)"
	case "privileged":
		return 5, "privileged identity " + user
	}
	return 0, ""
}

// ScoreEvent computes the event's contributions and records each one.
// Returns the contributions recorded (possibly empty). It never returns an
// error for "no contribution" — only for persistence failures.
func (s *EventScorer) ScoreEvent(ctx context.Context, ev *event.Event) ([]Contribution, error) {
	if ev == nil {
		return nil, nil
	}
	var out []Contribution
	record := func(entityType, value string, points float64, reason string) {
		if points == 0 || value == "" {
			return
		}
		out = append(out, Contribution{
			EntityType:  entityType,
			EntityValue: value,
			SourceType:  "event",
			SourceID:    "event-scorer",
			Description: reason,
			Points:      points,
			EventID:     ev.ID,
		})
	}

	sev := severityBase(ev.Severity)
	if ev.Host != "" {
		record("host", ev.Host, sev, "severity base "+ev.Severity)
		if p, reason := s.assetPoints(ctx, ev.Host); p > 0 {
			record("host", ev.Host, p, reason)
		}
	}
	if p, reason := s.userPoints(ctx, ev.User); p > 0 {
		record("user", ev.User, p, reason)
	}

	for i := range out {
		if err := s.risk.Record(ctx, out[i]); err != nil {
			return out, fmt.Errorf("record risk contribution: %w", err)
		}
	}
	return out, nil
}
