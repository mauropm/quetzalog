package findings

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Feedback is one analyst label for a finding (spec §55). One label per
// (finding, analyst); re-submission replaces the analyst's own label.
type Feedback struct {
	FindingID string    `json:"finding_id"`
	Label     string    `json:"label"`
	Reason    string    `json:"reason,omitempty"`
	Analyst   string    `json:"analyst"`
	CreatedAt time.Time `json:"created_at"`
}

// Valid feedback labels.
var feedbackLabels = map[string]bool{
	"true_positive":     true,
	"false_positive":    true,
	"benign":            true,
	"expected_behavior": true,
	"accepted_risk":     true,
}

// labelsRequiringReason must carry an analyst-written reason.
var labelsRequiringReason = map[string]bool{
	"false_positive": true,
	"accepted_risk":  true,
}

// ValidateFeedback checks a feedback payload before it is stored.
func ValidateFeedback(f *Feedback) error {
	if f == nil {
		return fmt.Errorf("nil feedback")
	}
	if f.FindingID == "" {
		return fmt.Errorf("finding_id is required")
	}
	label := strings.TrimSpace(f.Label)
	if !feedbackLabels[label] {
		return fmt.Errorf("invalid feedback label %q (valid: true_positive, false_positive, benign, expected_behavior, accepted_risk)", label)
	}
	f.Label = label
	if labelsRequiringReason[f.Label] && strings.TrimSpace(f.Reason) == "" {
		return fmt.Errorf("reason is required for label %q", f.Label)
	}
	if strings.TrimSpace(f.Analyst) == "" {
		return fmt.Errorf("analyst is required")
	}
	return nil
}

// AddFeedback records (or replaces) an analyst's label for a finding.
func (s *Store) AddFeedback(ctx context.Context, fb *Feedback) error {
	if err := ValidateFeedback(fb); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO finding_feedback (finding_id, label, reason, analyst, created_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(finding_id, analyst) DO UPDATE SET
		   label = excluded.label,
		   reason = excluded.reason,
		   created_at = excluded.created_at`,
		fb.FindingID, fb.Label, fb.Reason, fb.Analyst, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("add finding feedback: %w", err)
	}
	return nil
}

// FeedbackForFinding lists all analyst labels for one finding.
func (s *Store) FeedbackForFinding(ctx context.Context, findingID string) ([]Feedback, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT finding_id, label, reason, analyst, created_at FROM finding_feedback
		 WHERE finding_id = ? ORDER BY created_at DESC`, findingID)
	if err != nil {
		return nil, fmt.Errorf("list finding feedback: %w", err)
	}
	defer rows.Close()
	out := []Feedback{}
	for rows.Next() {
		var fb Feedback
		if err := rows.Scan(&fb.FindingID, &fb.Label, &fb.Reason, &fb.Analyst, &fb.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan finding feedback: %w", err)
		}
		out = append(out, fb)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate finding feedback: %w", err)
	}
	return out, nil
}

// DetectionFeedbackStats summarizes analyst feedback for findings produced by
// one detection rule. Used for the rolling false-positive rate shown on the
// rule page (informational in v1 — no silent weight changes, spec §55).
type DetectionFeedbackStats struct {
	Total        int            `json:"total"`
	ByLabel      map[string]int `json:"by_label"`
	FalsePosRate float64        `json:"false_positive_rate"`
}

// FeedbackStatsForDetection aggregates labels over findings whose
// detection_id matches the rule.
func (s *Store) FeedbackStatsForDetection(ctx context.Context, detectionID string) (*DetectionFeedbackStats, error) {
	if detectionID == "" {
		return nil, fmt.Errorf("empty detection ID")
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT ff.label, COUNT(*) FROM finding_feedback ff
		 JOIN findings f ON f.id = ff.finding_id
		 WHERE f.detection_id = ?
		 GROUP BY ff.label`, detectionID)
	if err != nil {
		return nil, fmt.Errorf("feedback stats: %w", err)
	}
	defer rows.Close()

	stats := &DetectionFeedbackStats{ByLabel: map[string]int{}}
	for rows.Next() {
		var label string
		var n int
		if err := rows.Scan(&label, &n); err != nil {
			return nil, fmt.Errorf("scan feedback stats: %w", err)
		}
		stats.ByLabel[label] = n
		stats.Total += n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate feedback stats: %w", err)
	}
	if stats.Total > 0 {
		stats.FalsePosRate = float64(stats.ByLabel["false_positive"]) / float64(stats.Total)
	}
	return stats, nil
}
