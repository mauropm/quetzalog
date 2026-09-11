// Package ast defines the Quetzalog SPL abstract syntax tree: the single
// contract shared by the parser, the serializer, the visual builder, the
// query planner/executor, the API and the tests. Nothing in the product
// concatenates SPL strings directly; text is produced by the serializer and
// consumed by the parser, both of which operate on these nodes.
package ast

import (
	"errors"
	"time"
)

// ErrInvalidQuery marks errors that originate from malformed or unsupported user
// input (bad SPL, unknown aggregation, invalid literal). Callers map these to a
// client-side 4xx response; anything not wrapping this sentinel is a server error.
var ErrInvalidQuery = errors.New("invalid spl query")

// Node is implemented by every AST node.
type Node interface {
	NodeType() string
}

// Expr is a boolean / leaf expression node. A single struct is used so the
// wire (JSON) representation is a stable, versioned discriminated union keyed
// by Kind.
type Expr struct {
	Kind   string   `json:"kind"`             // and|or|not|cmp|in|isnull|like
	Op     string   `json:"op,omitempty"`     // cmp: = != < <= > >=
	Field  string   `json:"field,omitempty"`  // cmp/in/isnull/like
	Value  string   `json:"value,omitempty"`  // cmp literal
	Args   []*Expr  `json:"args,omitempty"`   // and/or
	Arg    *Expr    `json:"arg,omitempty"`    // not
	Values []string `json:"values,omitempty"` // in
	Negate bool     `json:"negate,omitempty"` // in/like/isnull negation
	Pattern string `json:"pattern,omitempty"` // like pattern
}

// Expr constructor helpers (used by parser, builder and tests).
func And(args ...*Expr) *Expr   { return &Expr{Kind: "and", Args: args} }
func Or(args ...*Expr) *Expr    { return &Expr{Kind: "or", Args: args} }
func Not(a *Expr) *Expr         { return &Expr{Kind: "not", Arg: a} }
func Cmp(field, op, val string) *Expr { return &Expr{Kind: "cmp", Field: field, Op: op, Value: val} }
func In(field string, neg bool, vals ...string) *Expr { return &Expr{Kind: "in", Field: field, Negate: neg, Values: vals} }
func IsNull(field string, neg bool) *Expr { return &Expr{Kind: "isnull", Field: field, Negate: neg} }
func Like(field string, neg bool, pattern string) *Expr { return &Expr{Kind: "like", Field: field, Negate: neg, Pattern: pattern} }

// SearchNode is the leading search command. The single source of truth is
// Fields + Text (classic flat form) plus Expr (the general boolean tree). The
// planner/serializer prefer Expr when present. Data-source selectors such as
// index/sourcetype/source/host are ordinary field predicates, not parallel state.
type SearchNode struct {
	Fields map[string]string `json:"fields,omitempty"` // key=value pairs (flat AND form)
	Text   string            `json:"text,omitempty"`   // free-text search term(s)
	Expr   *Expr             `json:"expr,omitempty"`    // general boolean filter tree
}

func (s *SearchNode) NodeType() string { return "Search" }

// WhereNode filters using a boolean expression. Conditions is a flattened view
// of pure AND comparisons kept for the classic planner path.
type WhereNode struct {
	Conditions []Condition `json:"conditions,omitempty"`
	Expr       *Expr       `json:"expr,omitempty"`
}

func (w *WhereNode) NodeType() string { return "Where" }

// Condition is a flat field/operator/value comparison.
type Condition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// Aggregation describes one aggregate function in stats/eventstats/timechart.
type Aggregation struct {
	Function string `json:"func"`
	Field    string `json:"field,omitempty"`
	Alias    string `json:"alias,omitempty"`
}

// StatsNode performs aggregation with an optional group-by.
type StatsNode struct {
	Aggs    []Aggregation `json:"aggs"`
	GroupBy []string      `json:"groupby,omitempty"`
}

func (s *StatsNode) NodeType() string { return "Stats" }

// SortField pairs a field with a direction.
type SortField struct {
	Field string `json:"field"`
	Desc  bool   `json:"desc"`
}

// SortNode sorts results.
type SortNode struct {
	Fields []SortField `json:"fields"`
}

func (s *SortNode) NodeType() string { return "Sort" }

// HeadNode keeps the first N results.
type HeadNode struct {
	N int `json:"n"`
}

func (h *HeadNode) NodeType() string { return "Head" }

// TailNode keeps the last N results.
type TailNode struct {
	N int `json:"n"`
}

func (t *TailNode) NodeType() string { return "Tail" }

// DedupNode removes duplicates on a field.
type DedupNode struct {
	Field string `json:"field"`
}

func (d *DedupNode) NodeType() string { return "Dedup" }

// RenameNode renames fields.
type RenameNode struct {
	Mappings map[string]string `json:"-"`
	MappingsOrdered []RenamePair `json:"mappings,omitempty"`
}

// RenamePair is an ordered from/to rename used on the wire.
type RenamePair struct {
	From string `json:"from"`
	To   string `json:"to"`
}

func (r *RenameNode) NodeType() string { return "Rename" }

// TableNode projects an ordered set of columns.
type TableNode struct {
	Fields []string `json:"fields"`
}

func (t *TableNode) NodeType() string { return "Table" }

// FieldsNode keeps ("-") drops a set of fields. Include=true keeps, false drops.
type FieldsNode struct {
	Include bool     `json:"include"`
	Fields  []string `json:"fields"`
}

func (f *FieldsNode) NodeType() string { return "Fields" }

// EvalAssignment is one `field=expr` produced by eval.
type EvalAssignment struct {
	Field string `json:"field"`
	Expr  string `json:"expr"`
}

// EvalNode computes derived fields. Field/Expr carry the primary (first)
// assignment for the classic path; Assignments is the full ordered list.
type EvalNode struct {
	Field       string           `json:"-"`
	Expr        string           `json:"-"`
	Assignments []EvalAssignment `json:"assignments"`
}

func (e *EvalNode) NodeType() string { return "Eval" }

// TimechartNode is a time-bucketed aggregation.
type TimechartNode struct {
	Func    Aggregation `json:"agg"`
	Span    string      `json:"span,omitempty"`
	GroupBy []string    `json:"groupby,omitempty"`
}

func (t *TimechartNode) NodeType() string { return "Timechart" }

// RexNode extracts fields with a regular expression.
type RexNode struct {
	Field   string `json:"field,omitempty"`   // source field (default _raw/message)
	Pattern string `json:"pattern"`             // regex with (?<name>...) groups
	Rename  string `json:"alias,omitempty"`     // optional rename of first group
	Mode    string `json:"mode,omitempty"`      // multimatch|singlematch
}

func (r *RexNode) NodeType() string { return "Rex" }

// BinNode buckets a numeric/time field.
type BinNode struct {
	Field string `json:"field"`
	Span  string `json:"span,omitempty"`
}

func (b *BinNode) NodeType() string { return "Bin" }

// LookupNode enriches events from an external table.
type LookupNode struct {
	Lookup       string   `json:"lookup"`
	InputField   string   `json:"inputfield"`
	OutputFields []string `json:"outputfields,omitempty"`
	Append       bool     `json:"append,omitempty"`
}

func (l *LookupNode) NodeType() string { return "Lookup" }

// EventstatsNode adds aggregate columns without collapsing rows.
type EventstatsNode struct {
	Aggs    []Aggregation `json:"aggs"`
	GroupBy []string      `json:"groupby,omitempty"`
}

func (e *EventstatsNode) NodeType() string { return "Eventstats" }

// StreamstatsNode computes windowed/running aggregates.
type StreamstatsNode struct {
	Aggs    []Aggregation `json:"aggs"`
	GroupBy []string      `json:"groupby,omitempty"`
	Window  int           `json:"window,omitempty"`
}

func (s *StreamstatsNode) NodeType() string { return "Streamstats" }

// UnsupportedNode preserves a command the visual builder cannot represent so a
// raw query is never destroyed on parse. Its Raw text is re-emitted verbatim.
type UnsupportedNode struct {
	Name string `json:"name"`
	Raw  string `json:"raw"`
}

func (u *UnsupportedNode) NodeType() string { return "Unsupported" }

// Query is the root node: an ordered pipeline of commands. The first command
// is the leading `search` node when present (see the Search accessor).
type Query struct {
	Version  int    `json:"version"`
	Commands []Node `json:"commands"`
}

func (q *Query) NodeType() string { return "Query" }

// Search returns the leading search node or nil. The parser and the visual
// builder always keep the search node as commands[0]; this is a convenience
// accessor, not a second source of truth.
func (q *Query) Search() *SearchNode {
	if q == nil || len(q.Commands) == 0 {
		return nil
	}
	if s, ok := q.Commands[0].(*SearchNode); ok {
		return s
	}
	return nil
}

// TimeRange carries an optional time window resolved by the caller.
type TimeRange struct {
	Earliest time.Time `json:"earliest,omitempty"`
	Latest   time.Time `json:"latest,omitempty"`
}
