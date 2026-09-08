package risk

import (
	"context"
	"database/sql"
	"fmt"
	"quetzalog/pkg/event"
	"time"
)

type Scorer struct {
	Config ScoringConfig
	db     *sql.DB
}

type ScoringConfig struct {
	SeverityWeights map[string]float64
	MaxEventScore   float64
	MaxEntityScore  float64
	MaxFreqScore    float64
	DecayHours      float64
}

type ScoreResult struct {
	EventScore     float64 `json:"event_score"`
	EntityScore    float64 `json:"entity_score"`
	FrequencyScore float64 `json:"frequency_score"`
	TotalScore     float64 `json:"total_score"`
}

var DefaultConfig = ScoringConfig{
	SeverityWeights: map[string]float64{
		"debug":     0,
		"info":      5,
		"notice":    10,
		"warning":   20,
		"err":       40,
		"critical":  60,
		"alert":     80,
		"emergency": 100,
	},
	MaxEventScore:  100,
	MaxEntityScore: 50,
	MaxFreqScore:   50,
	DecayHours:     24,
}

var DefaultBadIPs = map[string]bool{
	"0.0.0.0":         true,
	"127.0.0.1":       false,
	"255.255.255.255": true,
}

var DefaultBadUsers = map[string]bool{}

func NewScorer(config ScoringConfig, db *sql.DB) *Scorer {
	if config.SeverityWeights == nil {
		config.SeverityWeights = DefaultConfig.SeverityWeights
	}
	if config.MaxEventScore == 0 {
		config.MaxEventScore = DefaultConfig.MaxEventScore
	}
	if config.MaxEntityScore == 0 {
		config.MaxEntityScore = DefaultConfig.MaxEntityScore
	}
	if config.MaxFreqScore == 0 {
		config.MaxFreqScore = DefaultConfig.MaxFreqScore
	}
	if config.DecayHours == 0 {
		config.DecayHours = DefaultConfig.DecayHours
	}

	return &Scorer{Config: config, db: db}
}

func (s *Scorer) ScoreEvent(ctx context.Context, ev *event.Event) (*ScoreResult, error) {
	eventScore := s.EventScore(ev)
	entityScore := s.EntityScore(ctx, ev.SourceIP, ev.User, ev.Host)

	window := time.Duration(s.Config.DecayHours) * time.Hour
	frequencyScore := s.FrequencyScore(ctx, ev.SourceIP, ev.User, ev.Host, window)

	total := eventScore + entityScore + frequencyScore
	if total > 100 {
		total = 100
	}

	return &ScoreResult{
		EventScore:     eventScore,
		EntityScore:    entityScore,
		FrequencyScore: frequencyScore,
		TotalScore:     total,
	}, nil
}

func (s *Scorer) ScoreEvents(ctx context.Context, events []*event.Event) ([]*ScoreResult, error) {
	results := make([]*ScoreResult, 0, len(events))

	for _, ev := range events {
		result, err := s.ScoreEvent(ctx, ev)
		if err != nil {
			return nil, fmt.Errorf("score event %s: %w", ev.ID, err)
		}
		results = append(results, result)
	}

	return results, nil
}

func (s *Scorer) EventScore(e *event.Event) float64 {
	severity := event.ParseSeverity(e.Severity)
	weight, ok := s.Config.SeverityWeights[severity]
	if !ok {
		weight = 10
	}

	score := weight * (s.Config.MaxEventScore / 100)
	if score > s.Config.MaxEventScore {
		score = s.Config.MaxEventScore
	}

	return score
}

func (s *Scorer) EntityScore(ctx context.Context, sourceIP, user, host string) float64 {
	var score float64

	if sourceIP != "" {
		if DefaultBadIPs[sourceIP] {
			score += s.Config.MaxEntityScore * 0.8
		}
	}

	if user != "" {
		if DefaultBadUsers[user] {
			score += s.Config.MaxEntityScore * 0.9
		}
	}

	if host != "" {
		if score == 0 {
			score += 5
		}
	}

	if score > s.Config.MaxEntityScore {
		score = s.Config.MaxEntityScore
	}

	return score
}

func (s *Scorer) FrequencyScore(ctx context.Context, sourceIP, user, host string, window time.Duration) float64 {
	if s.db == nil {
		return 0
	}

	var totalEvents int64

	counts := []struct {
		entity string
		column string
	}{
		{sourceIP, "source_ip"},
		{user, "user"},
		{host, "host"},
	}

	for _, c := range counts {
		if c.entity == "" {
			continue
		}

		var count int64
		query := fmt.Sprintf(
			"SELECT COUNT(*) FROM events WHERE %s = ? AND received_at >= ?",
			c.column,
		)
		err := s.db.QueryRow(query, c.entity, time.Now().Add(-window).Format(time.RFC3339)).Scan(&count)
		if err != nil {
			continue
		}
		totalEvents += count
	}

	if totalEvents == 0 {
		return 0
	}

	score := s.Normalize(float64(totalEvents), 1000)
	score *= s.Config.MaxFreqScore
	if score > s.Config.MaxFreqScore {
		score = s.Config.MaxFreqScore
	}

	return score
}

func (s *Scorer) Normalize(score float64, maxScore float64) float64 {
	if maxScore <= 0 {
		return 0
	}
	n := score / maxScore
	if n > 1 {
		return 1
	}
	if n < 0 {
		return 0
	}
	return n
}
