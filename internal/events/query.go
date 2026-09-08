package events

import "time"

// Query represents a search query for filtering and paginating events.
type Query struct {
	Text          string            // FTS5 text search
	Source        string            // filter by source
	SourceType    string            // filter by source type
	Host          string            // filter by host
	Service       string            // filter by service
	Severity      string            // filter by severity
	EventType     string            // filter by event type
	Category      string            // filter by category
	Action        string            // filter by action
	Outcome       string            // filter by outcome
	User          string            // filter by user
	SourceIP      string            // filter by source IP
	DestinationIP string            // filter by destination IP
	Start         time.Time         // filter by start timestamp (inclusive)
	End           time.Time         // filter by end timestamp (inclusive)
	Limit         int               // page size (default 100)
	Offset        int               // page offset
	SortBy        string            // column to sort by (default "timestamp")
	SortOrder     string            // "asc" or "desc" (default "desc")
	Attributes    map[string]string // key=value filters on attributes
}

// NewQuery creates a Query with sensible defaults.
func NewQuery() Query {
	return Query{
		Limit:     100,
		SortBy:    "timestamp",
		SortOrder: "desc",
	}
}
