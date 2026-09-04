package ast

import "time"

type Node interface {
	NodeType() string
}

// SearchNode - base search command
type SearchNode struct {
	Fields map[string]string // key=value pairs
	Text   string            // free-text search
}

func (s *SearchNode) NodeType() string { return "Search" }

// WhereNode - conditional filtering
type WhereNode struct {
	Conditions []Condition
}

func (w *WhereNode) NodeType() string { return "Where" }

type Condition struct {
	Field    string
	Operator string // =, !=, >, <, >=, <=, *=, "in", "not in", regex
	Value    string
}

// StatsNode - aggregation
type StatsNode struct {
	Aggs      []Aggregation
	GroupBy   []string
}

func (s *StatsNode) NodeType() string { return "Stats" }

type Aggregation struct {
	Function string // count, values, dc, sum, avg, min, max
	Field    string // "*" for count, or a field name
	Alias    string
}

// SortNode - sorting
type SortNode struct {
	Fields []SortField
}

func (s *SortNode) NodeType() string { return "Sort" }

type SortField struct {
	Field string
	Desc  bool
}

// HeadNode - limit results
type HeadNode struct {
	N int
}

func (h *HeadNode) NodeType() string { return "Head" }

// TailNode - show last N results
type TailNode struct {
	N int
}

func (t *TailNode) NodeType() string { return "Tail" }

// DedupNode - remove duplicates
type DedupNode struct {
	Field string
}

func (d *DedupNode) NodeType() string { return "Dedup" }

// RenameNode - rename fields
type RenameNode struct {
	Mappings map[string]string
}

func (r *RenameNode) NodeType() string { return "Rename" }

// TableNode - format output
type TableNode struct {
	Fields []string
}

func (t *TableNode) NodeType() string { return "Table" }

// EvalNode - compute fields
type EvalNode struct {
	Field string
	Expr  string
}

func (e *EvalNode) NodeType() string { return "Eval" }

// TimechartNode - time-based chart
type TimechartNode struct {
	Func    Aggregation
	Span    string
	GroupBy []string
}

func (t *TimechartNode) NodeType() string { return "Timechart" }

// RexNode - regex extraction
type RexNode struct {
	Field   string
	Pattern string
	Rename  string
	Mode    string // "multimatch" or "singlematch"
}

func (r *RexNode) NodeType() string { return "Rex" }

// Query is the root AST node
type Query struct {
	Commands []Node
}

func (q *Query) NodeType() string { return "Query" }

// TimeRange holds optional time range information
type TimeRange struct {
	Earliest time.Time
	Latest   time.Time
}
