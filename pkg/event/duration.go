package event

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseDuration parses a duration string with optional suffixes and relative time markers.
//
// Supported formats:
//   - Absolute time: "2006-01-02 15:04:05" or RFC3339
//   - Negative duration from now: "-24h", "-30m", "-7d"
//   - Duration suffixes: "1h", "30m", "15s", "2d", "1w", "1M", "1y"
//   - Unit-only (defaults to hours): "h", "m", "s", "d"
//   - "now" returns the current time
//   - "yesterday" returns the same time yesterday
//   - "today" returns midnight today
//   - "tomorrow" returns midnight tomorrow
func ParseDuration(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty duration string")
	}

	now := time.Now()

	switch strings.ToLower(s) {
	case "now":
		return now, nil
	case "yesterday":
		return now.AddDate(0, 0, -1), nil
	case "today":
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()), nil
	case "tomorrow":
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).AddDate(0, 0, 1), nil
	}

	// Handle negative durations (relative offsets from now)
	if strings.HasPrefix(s, "-") {
		return parseRelativeDuration(s[1:], now, true)
	}

	// Try parsing as absolute time first
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t, nil
	}
	if t := ParseTimestamp(s); !t.IsZero() {
		return t, nil
	}

	// Parse as relative duration from now (positive means ago)
	return parseRelativeDuration(s, now, false)
}

// ParseDurationFrom parses a duration string relative to a base time.
func ParseDurationFrom(s string, base time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty duration string")
	}

	if base.IsZero() {
		base = time.Now()
	}

	switch strings.ToLower(s) {
	case "now":
		return base, nil
	case "yesterday":
		return base.AddDate(0, 0, -1), nil
	case "today":
		return time.Date(base.Year(), base.Month(), base.Day(), 0, 0, 0, 0, base.Location()), nil
	case "tomorrow":
		return time.Date(base.Year(), base.Month(), base.Day(), 0, 0, 0, 0, base.Location()).AddDate(0, 0, 1), nil
	}

	// Handle negative durations
	if strings.HasPrefix(s, "-") {
		return parseRelativeDuration(s[1:], base, true)
	}

	// Try parsing as absolute time
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t, nil
	}
	if t := ParseTimestamp(s); !t.IsZero() {
		return t, nil
	}

	// Parse as relative duration
	return parseRelativeDuration(s, base, false)
}

func parseRelativeDuration(s string, ref time.Time, negate bool) (time.Time, error) {
	var d time.Duration

	// Try parsing the whole string as a duration (e.g., "1h30m", "24h")
	if dur, err := time.ParseDuration(s); err == nil {
		if negate {
			dur = -dur
		}
		return ref.Add(dur), nil
	}

	// Parse unit-only suffixes: "h", "m", "s", "d", "w", "M", "y"
	unit := strings.ToLower(s)
	if len(unit) >= 1 {
		lastChar := unit[len(unit)-1:]

		var quantity int
		var err error
		if len(unit) > 1 {
			quantity, err = strconv.Atoi(strings.TrimSuffix(unit, lastChar))
			if err != nil {
				return time.Time{}, fmt.Errorf("invalid duration quantity: %w", err)
			}
		} else {
			quantity = 1
		}

		switch lastChar {
		case "h":
			d = time.Duration(quantity) * time.Hour
		case "m":
			d = time.Duration(quantity) * time.Minute
		case "s":
			d = time.Duration(quantity) * time.Second
		case "d":
			d = time.Duration(quantity) * 24 * time.Hour
		case "w":
			d = time.Duration(quantity) * 7 * 24 * time.Hour
		case "M":
			// Approximate: 30 days
			d = time.Duration(quantity) * 30 * 24 * time.Hour
		case "y":
			// Approximate: 365 days
			d = time.Duration(quantity) * 365 * 24 * time.Hour
		default:
			return time.Time{}, fmt.Errorf("unsupported duration suffix: %q. Use h, m, s, d, w, M, or y", lastChar)
		}

		if negate {
			return ref.Add(-d), nil
		}
		return ref.Add(-d), nil
	}

	return time.Time{}, fmt.Errorf("unable to parse duration: %q", s)
}

// ParseTimeRange parses a time range string in the format "start,end" or "start-end"
// and returns the start and end times.
func ParseTimeRange(s string) (time.Time, time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, time.Time{}, fmt.Errorf("empty time range string")
	}

	// Try splitting by comma or dash (but not negative numbers)
	var parts []string

	if strings.Contains(s, ",") {
		parts = strings.SplitN(s, ",", 2)
	} else if strings.Contains(s, "-") {
		// Split on the first "-" that isn't at position 0 (negative numbers)
		for i := 1; i < len(s); i++ {
			if s[i] == '-' && s[i-1] != '-' {
				parts = []string{s[:i], s[i+1:]}
				break
			}
		}
		if len(parts) == 0 {
			parts = strings.SplitN(s, "-", 2)
		}
	} else {
		return time.Time{}, time.Time{}, fmt.Errorf("time range must contain a separator (comma or dash)")
	}

	if len(parts) != 2 {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid time range format: %q", s)
	}

	start, err := ParseDuration(strings.TrimSpace(parts[0]))
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("failed to parse start time: %w", err)
	}

	end, err := ParseDuration(strings.TrimSpace(parts[1]))
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("failed to parse end time: %w", err)
	}

	return start, end, nil
}
