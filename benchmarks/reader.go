package main

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

// printReport formats and prints the benchmark results as JSON.
func printReport(results []BenchResult) error {
	report := &BenchReport{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Results:   results,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// formatSummary outputs a human-readable summary of benchmark results.
func formatSummary(results []BenchResult) string {
	var sb strings.Builder
	sb.WriteString("\n=== Summary ===\n")
	for _, r := range results {
		sb.WriteString(r.String() + "\n")
	}
	return sb.String()
}

// printJSONResult is an alias for printReport to satisfy the public API surface.
func printJSONResult(results []BenchResult) error {
	return printReport(results)
}
