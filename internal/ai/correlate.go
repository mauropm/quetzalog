package ai

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// CorrelateResult is the "open in Search" payload for a stored analysis: an
// SPL filter that correlates every entity the analysis considered, plus the
// time window it reasoned about. It never executes anything — the operator
// reviews and runs the query in the Search page.
type CorrelateResult struct {
	Query    string       `json:"query"`
	Earliest string       `json:"earliest,omitempty"`
	Latest   string       `json:"latest,omitempty"`
	Entities CorrelateEnt `json:"entities"`
}

// CorrelateEnt lists the entities woven into the query.
type CorrelateEnt struct {
	Users []string `json:"users"`
	Hosts []string `json:"hosts"`
	IPs   []string `json:"ips"`
}

var (
	correlateIPRe = regexp.MustCompile(`\b((?:\d{1,3}\.){3}\d{1,3})\b`)
	// ISO-ish timestamps as models write them: 2026-09-14T20:00:00Z,
	// 2026-09-14 20:00, ...
	correlateTSRe = regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:?\d{2})?`)
)

const (
	maxCorrelateUsers = 5
	maxCorrelateHosts = 5
	maxCorrelateIPs   = 8
)

// CorrelateQuery builds the correlation search for one stored analysis from
// its persisted context and text: entities come from the structured context,
// any IP the model additionally named in the recommendation/summary is added,
// and the time window comes from explicit timestamps in the analysis text
// (falling back to the event range, padded).
func (s *Service) CorrelateQuery(ctx context.Context, analysisID string) (CorrelateResult, error) {
	_, a, c, err := s.store.Get(ctx, analysisID)
	if err != nil {
		return CorrelateResult{}, err
	}
	if a == nil {
		return CorrelateResult{}, fmt.Errorf("%w: no completed analysis to correlate", ErrNoAnalysis)
	}
	if c == nil {
		return CorrelateResult{}, fmt.Errorf("%w: analysis context missing", ErrNoAnalysis)
	}

	ra := a.RecommendedAction
	entities := CorrelateEnt{
		Users: capList(c.Entities.Users, maxCorrelateUsers),
		Hosts: capList(c.Entities.Hosts, maxCorrelateHosts),
		IPs:   capList(c.Entities.IPs, maxCorrelateIPs),
	}

	// IPs the model named in its own words but that are absent from the
	// structured entity summary (e.g. entities of related findings).
	ipSet := map[string]bool{}
	for _, ip := range entities.IPs {
		ipSet[ip] = true
	}
	text := strings.Join([]string{
		ra.Description,
		a.Summary,
		a.WhatIsHappening,
	}, " ")
	for _, m := range correlateIPRe.FindAllString(text, -1) {
		if ipSet[m] || !validIP(m) {
			continue
		}
		if len(entities.IPs) >= maxCorrelateIPs {
			break
		}
		ipSet[m] = true
		entities.IPs = append(entities.IPs, m)
	}

	earliest, latest := correlationWindow(a, c)
	return CorrelateResult{
		Query:    correlationQuery(entities),
		Earliest: earliest,
		Latest:   latest,
		Entities: entities,
	}, nil
}

// correlationWindow prefers timestamps the model explicitly reasoned about;
// otherwise it spans the analyzed events padded by 15 minutes each side.
func correlationWindow(a *Analysis, c *FindingContext) (string, string) {
	text := a.RecommendedAction.Description + " " + a.Summary + " " + a.WhatIsHappening
	var lo, hi time.Time
	found := false
	for _, m := range correlateTSRe.FindAllString(text, -1) {
		t, err := time.Parse(time.RFC3339, normalizeTS(m))
		if err != nil {
			continue
		}
		if !found || t.Before(lo) {
			lo = t
		}
		if !found || t.After(hi) {
			hi = t
		}
		found = true
	}
	if found {
		// A single timestamp is a point in time; give it a ±30m window.
		if lo.Equal(hi) {
			lo, hi = lo.Add(-30*time.Minute), hi.Add(30*time.Minute)
		}
		return lo.Format(time.RFC3339), hi.Format(time.RFC3339)
	}
	return eventWindow(c)
}

// eventWindow spans the context events, padded. When no events were captured
// it falls back to the finding's own first/last seen.
func eventWindow(c *FindingContext) (string, string) {
	var lo, hi time.Time
	for i, ev := range c.Events {
		if i == 0 || ev.Timestamp.Before(lo) {
			lo = ev.Timestamp
		}
		if i == 0 || ev.Timestamp.After(hi) {
			hi = ev.Timestamp
		}
	}
	if lo.IsZero() {
		lo, hi = c.Finding.FirstSeen, c.Finding.LastSeen
	}
	if lo.IsZero() {
		return "", ""
	}
	lo = lo.Add(-15 * time.Minute)
	hi = hi.Add(15 * time.Minute)
	return lo.Format(time.RFC3339), hi.Format(time.RFC3339)
}

// normalizeTS rewrites the casual forms models use into RFC3339:
// "2026-09-14 20:00" -> "2026-09-14T20:00:00Z".
func normalizeTS(s string) string {
	s = strings.Replace(s, " ", "T", 1)
	if !strings.Contains(s, ":") || strings.Count(s, ":") == 1 {
		s += ":00"
	}
	if !strings.HasSuffix(s, "Z") && !regexp.MustCompile(`[+-]\d{2}:\d{2}$`).MatchString(s) {
		s += "Z"
	}
	return s
}

func validIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

// correlationQuery renders the entity OR-set as a single-line SPL filter.
// No pipeline is appended so the operator can compose with the Search page's
// time/limit controls or their own commands.
func correlationQuery(e CorrelateEnt) string {
	var ors []string
	for _, u := range e.Users {
		ors = append(ors, fmt.Sprintf("user=%q", u))
	}
	for _, h := range e.Hosts {
		ors = append(ors, fmt.Sprintf("host=%q", h))
	}
	for _, ip := range e.IPs {
		ors = append(ors, fmt.Sprintf("source_ip=%q", ip))
		ors = append(ors, fmt.Sprintf("destination_ip=%q", ip))
	}
	return strings.Join(ors, " OR ")
}

func capList(in []string, n int) []string {
	if len(in) > n {
		return in[:n]
	}
	return in
}
