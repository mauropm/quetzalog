package detections

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"quetzalog/internal/findings"
	"quetzalog/internal/risk"
	"quetzalog/internal/spl/executor"
)

// splRunLimit bounds result rows consumed per SPL detection run.
const splRunLimit = 1000

// splEntityColumns maps SPL result columns to finding entity types.
// Only these columns feed entity/risk attribution; everything else is
// grouping evidence.
var splEntityColumns = map[string]string{
	"user":           "user",
	"host":           "host",
	"source_ip":      "ip",
	"src_ip":         "ip",
	"destination_ip": "ip",
	"dest_ip":        "ip",
	"process":        "process",
	"service":        "service",
}

// splGroup is one deduplicated set of SPL result rows sharing the same
// non-numeric column values.
type splGroup struct {
	key      string
	entities []string
	rows     []map[string]any
}

// runSPLRule executes a kind=spl rule through the full SPL engine.
// Result rows whose first numeric column reaches the optional threshold
// become findings; when a threshold is not set, every row is a finding.
// Rows sharing the same non-numeric column values are deduplicated into
// one finding (group_by semantics from the SPL `by` fields).
func (s *Store) runSPLRule(ctx context.Context, rule *DetectionRule, db *sql.DB, findingStore *findings.Store, riskStore *risk.EntityRiskStore, start, end time.Time) (*FindingRunResult, error) {
	if rule == nil {
		return nil, fmt.Errorf("nil detection rule")
	}
	if db == nil {
		return nil, fmt.Errorf("nil database")
	}
	if findingStore == nil {
		return nil, fmt.Errorf("nil finding store")
	}

	started := time.Now()
	result := &FindingRunResult{}

	resp, err := executor.Run(ctx, db, rule.Query, executor.RunOptions{
		Limit:    splRunLimit,
		Earliest: start,
		Latest:   end,
	})
	if err != nil {
		return nil, fmt.Errorf("run spl detection: %w", err)
	}
	if resp == nil || len(resp.Rows) == 0 {
		result.Duration = time.Since(started)
		return result, nil
	}

	result.Total = len(resp.Rows)

	threshold := 0
	if rule.Threshold != nil {
		threshold = rule.Threshold.Count
	}
	measureCol := ""
	if threshold > 0 && len(resp.Columns) > 0 {
		measureCol = resp.Columns[0]
	}

	// Group rows by their non-numeric (i.e. "by") columns.
	groups := map[string]*splGroup{}
	var order []string

	for _, row := range resp.Rows {
		if measureCol != "" {
			v := row[measureCol]
			n, ok := toFloat(v)
			if !ok || n < float64(threshold) {
				continue
			}
		}

		byParts := make([]string, 0, len(resp.Columns))
		ents := map[string]bool{}
		for _, col := range resp.Columns {
			if col == measureCol {
				continue
			}
			v, present := row[col]
			if !present {
				continue
			}
			if _, numeric := toFloat(v); numeric {
				continue
			}
			byParts = append(byParts, col+"="+fmt.Sprintf("%v", v))
			if et, known := splEntityColumns[strings.ToLower(col)]; known {
				ents[et+":"+fmt.Sprintf("%v", v)] = true
			}
		}

		key := "global"
		if len(byParts) > 0 {
			sort.Strings(byParts)
			key = strings.Join(byParts, ",")
		}
		g, ok := groups[key]
		if !ok {
			elist := make([]string, 0, len(ents))
			for e := range ents {
				elist = append(elist, e)
			}
			sort.Strings(elist)
			g = &splGroup{key: key, entities: elist}
			groups[key] = g
			order = append(order, key)
		}
		g.rows = append(g.rows, row)
	}

	dataSource := ""
	if len(rule.DataSources) > 0 {
		dataSource = rule.DataSources[0]
	}

	for _, key := range order {
		g := groups[key]
		created, isNew, err := s.upsertSPLFinding(ctx, rule, key, g, findingStore, riskStore, dataSource)
		if err != nil {
			return nil, err
		}
		result.Matched += len(g.rows)
		result.Findings = append(result.Findings, created.ID)
		if isNew {
			result.Created++
		}
	}

	result.Duration = time.Since(started)
	return result, nil
}

// upsertSPLFinding materializes one finding from a group of SPL result rows.
// No raw events ride along: the rows themselves are the evidence, and the
// known entity columns drive risk attribution.
func (s *Store) upsertSPLFinding(ctx context.Context, rule *DetectionRule, groupKey string, g *splGroup, findingStore *findings.Store, riskStore *risk.EntityRiskStore, dataSource string) (*findings.Finding, bool, error) {
	desc := rule.Description
	if len(g.rows) > 0 {
		b, err := json.Marshal(g.rows[:min(len(g.rows), 5)])
		if err == nil {
			summary := string(b)
			if len(summary) > 500 {
				summary = summary[:500] + "…"
			}
			desc = desc + "\n\nSPL result rows: " + summary
		}
	}
	if rule.Confidence > 0 {
		desc += fmt.Sprintf("\n(Rule confidence: %.2f)", rule.Confidence)
	}

	f, isNew, err := findingStore.CreateOrUpdateFromDetection(ctx, findings.FromDetectionArgs{
		RuleID:         rule.ID,
		RuleName:       rule.Name,
		GroupKey:       groupKey,
		Title:          rule.Name,
		Description:    desc,
		Severity:       rule.Severity,
		RiskScore:      rule.RiskScore,
		DataSource:     dataSource,
		MITRETactic:    rule.MITRETactic,
		MITRETechnique: rule.MITRETechnique,
		Tags:           rule.Tags,
		Matched:        len(g.rows),
		Entities:       g.entities,
	})
	if err != nil {
		return nil, false, fmt.Errorf("upsert spl finding: %w", err)
	}

	if isNew {
		s.callOnNewFinding(ctx, f)

		if riskStore != nil && f.RiskScore > 0 {
			for _, e := range f.Entities {
				parts := strings.SplitN(e, ":", 2)
				if len(parts) != 2 || parts[1] == "" {
					continue
				}
				et, ev := parts[0], parts[1]
				points := f.RiskScore
				if et == "process" {
					points = f.RiskScore / 2
				}
				_ = riskStore.Record(ctx, risk.Contribution{
					EntityType:  et,
					EntityValue: ev,
					SourceType:  "finding",
					SourceID:    f.ID,
					Description: fmt.Sprintf("%s (%s)", f.Title, f.Severity),
					Points:      points,
				})
			}
		}
	}

	return f, isNew, nil
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case string:
		f, err := strconv.ParseFloat(n, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}
