package ast

import (
	"encoding/json"
	"fmt"
	"strings"
)

// commandType is the wire discriminator for a command node.
func commandType(n Node) string {
	switch n.(type) {
	case *SearchNode:
		return "search"
	case *WhereNode:
		return "where"
	case *EvalNode:
		return "eval"
	case *FieldsNode:
		return "fields"
	case *TableNode:
		return "table"
	case *RenameNode:
		return "rename"
	case *StatsNode:
		return "stats"
	case *TimechartNode:
		return "timechart"
	case *SortNode:
		return "sort"
	case *HeadNode:
		return "head"
	case *TailNode:
		return "tail"
	case *DedupNode:
		return "dedup"
	case *RexNode:
		return "rex"
	case *BinNode:
		return "bin"
	case *LookupNode:
		return "lookup"
	case *EventstatsNode:
		return "eventstats"
	case *StreamstatsNode:
		return "streamstats"
	case *UnsupportedNode:
		return "unsupported"
	default:
		return "unknown"
	}
}

// CommandName reports the SPL command name of a node ("", for unknown).
func CommandName(n Node) string { return commandType(n) }

// SupportedCommands is the set of SPL commands the visual builder can fully
// round-trip. The registry is the single place to extend for a new command:
// add the node type, its (un)marshal case, its serializer and its execution.
var SupportedCommands = map[string]bool{
	"search": true, "where": true, "eval": true, "fields": true, "table": true,
	"rename": true, "stats": true, "timechart": true, "sort": true, "head": true,
	"tail": true, "dedup": true, "rex": true, "bin": true, "lookup": true,
	"eventstats": true, "streamstats": true,
}

// IsSupportedCommand reports whether a command name is builder-representable.
func IsSupportedCommand(name string) bool { return SupportedCommands[name] }

// UnsupportedCommands returns the ordered list of command names present in the
// query that the builder cannot represent.
func (q *Query) UnsupportedCommands() []string {
	var out []string
	for _, n := range q.Commands {
		name := commandType(n)
		if name == "unsupported" {
			if u, ok := n.(*UnsupportedNode); ok && u.Name != "" {
				out = append(out, u.Name)
				continue
			}
		}
		if !SupportedCommands[name] {
			out = append(out, name)
		}
	}
	return out
}

// Supported reports whether every command is builder-representable.
func (q *Query) Supported() bool { return len(q.UnsupportedCommands()) == 0 }

// wireCommand is the shared envelope for (un)marshalling a command union. All
// possible fields are optional; encoding/json drops the unset ones.
type wireCommand struct {
	Type        string            `json:"type"`
	Text        string            `json:"text,omitempty"`
	Fields      map[string]string `json:"fields,omitempty"`
	Expr        *Expr             `json:"expr,omitempty"`
	Conditions  []Condition       `json:"conditions,omitempty"`
	Assignments []EvalAssignment  `json:"assignments,omitempty"`
	Include     *bool             `json:"include,omitempty"`
	Columns     []string          `json:"columns,omitempty"`
	Mappings    []RenamePair      `json:"mappings,omitempty"`
	Aggs        []Aggregation     `json:"aggs,omitempty"`
	GroupBy     []string          `json:"groupby,omitempty"`
	Span        string            `json:"span,omitempty"`
	Agg         *Aggregation      `json:"agg,omitempty"`
	Sort        []SortField       `json:"sort,omitempty"`
	N           int               `json:"n,omitempty"`
	Field       string            `json:"field,omitempty"`
	Window      int               `json:"window,omitempty"`
	Lookup      string            `json:"lookup,omitempty"`
	OutputFields []string         `json:"outputfields,omitempty"`
	Append      bool              `json:"append,omitempty"`
	Pattern     string            `json:"pattern,omitempty"`
	Alias       string            `json:"alias,omitempty"`
	Mode        string            `json:"mode,omitempty"`
	Name        string            `json:"name,omitempty"`
	Raw         string            `json:"raw,omitempty"`
}

// MarshalJSON emits the stable wire form: {"version":1,"commands":[{...}]}
func (q *Query) MarshalJSON() ([]byte, error) {
	cmds := make([]wireCommand, 0, len(q.Commands))
	for _, n := range q.Commands {
		c, err := nodeToWire(n)
		if err != nil {
			return nil, err
		}
		cmds = append(cmds, c)
	}
	v := q.Version
	if v == 0 {
		v = 1
	}
	return json.Marshal(struct {
		Version  int           `json:"version"`
		Commands []wireCommand `json:"commands"`
	}{Version: v, Commands: cmds})
}

// UnmarshalJSON accepts the wire form produced by MarshalJSON (and sent by the
// visual builder), reconstructing the concrete command nodes.
func (q *Query) UnmarshalJSON(b []byte) error {
	var in struct {
		Version  int               `json:"version"`
		Commands []json.RawMessage `json:"commands"`
	}
	if err := json.Unmarshal(b, &in); err != nil {
		return err
	}
	q.Version = in.Version
	if q.Version == 0 {
		q.Version = 1
	}
	q.Commands = make([]Node, 0, len(in.Commands))
	for _, raw := range in.Commands {
		var head struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &head); err != nil {
			return fmt.Errorf("command: %w", err)
		}
		node, err := wireToNode(head.Type, raw)
		if err != nil {
			return err
		}
		q.Commands = append(q.Commands, node)
	}
	return nil
}

func nodeToWire(n Node) (wireCommand, error) {
	switch x := n.(type) {
	case *SearchNode:
		return wireCommand{Type: "search", Text: x.Text, Fields: x.Fields, Expr: x.Expr}, nil
	case *WhereNode:
		return wireCommand{Type: "where", Expr: x.Expr, Conditions: x.Conditions}, nil
	case *EvalNode:
		asg := x.Assignments
		if len(asg) == 0 && x.Field != "" {
			asg = []EvalAssignment{{Field: x.Field, Expr: x.Expr}}
		}
		return wireCommand{Type: "eval", Assignments: asg}, nil
	case *FieldsNode:
		inc := x.Include
		return wireCommand{Type: "fields", Include: &inc, Columns: x.Fields}, nil
	case *TableNode:
		return wireCommand{Type: "table", Columns: x.Fields}, nil
	case *RenameNode:
		return wireCommand{Type: "rename", Mappings: renamePairs(x)}, nil
	case *StatsNode:
		return wireCommand{Type: "stats", Aggs: x.Aggs, GroupBy: x.GroupBy}, nil
	case *TimechartNode:
		agg := x.Func
		return wireCommand{Type: "timechart", Span: x.Span, Agg: &agg, GroupBy: x.GroupBy}, nil
	case *SortNode:
		return wireCommand{Type: "sort", Sort: x.Fields}, nil
	case *HeadNode:
		return wireCommand{Type: "head", N: x.N}, nil
	case *TailNode:
		return wireCommand{Type: "tail", N: x.N}, nil
	case *DedupNode:
		return wireCommand{Type: "dedup", Field: x.Field}, nil
	case *RexNode:
		return wireCommand{Type: "rex", Field: x.Field, Pattern: x.Pattern, Alias: x.Rename, Mode: x.Mode}, nil
	case *BinNode:
		return wireCommand{Type: "bin", Field: x.Field, Span: x.Span}, nil
	case *LookupNode:
		return wireCommand{Type: "lookup", Lookup: x.Lookup, Field: x.InputField, OutputFields: x.OutputFields, Append: x.Append}, nil
	case *EventstatsNode:
		return wireCommand{Type: "eventstats", Aggs: x.Aggs, GroupBy: x.GroupBy}, nil
	case *StreamstatsNode:
		return wireCommand{Type: "streamstats", Aggs: x.Aggs, GroupBy: x.GroupBy, Window: x.Window}, nil
	case *UnsupportedNode:
		return wireCommand{Type: "unsupported", Name: x.Name, Raw: x.Raw}, nil
	default:
		return wireCommand{}, fmt.Errorf("unsupported node type %T", n)
	}
}

func wireToNode(kind string, raw json.RawMessage) (Node, error) {
	switch kind {
	case "search", "":
		var w wireCommand
		if err := json.Unmarshal(raw, &w); err != nil {
			return nil, err
		}
		sn := &SearchNode{Text: w.Text, Expr: w.Expr}
		sn.Fields = w.Fields
		if sn.Fields == nil {
			sn.Fields = map[string]string{}
		}
		return sn, nil
	case "where":
		var w wireCommand
		if err := json.Unmarshal(raw, &w); err != nil {
			return nil, err
		}
		wn := &WhereNode{Expr: w.Expr}
		if wn.Expr == nil && len(w.Conditions) > 0 {
			wn.Expr = conditionsToExpr(w.Conditions)
		}
		wn.Conditions = w.Conditions
		if len(wn.Conditions) == 0 {
			wn.Conditions = exprToConditions(wn.Expr)
		}
		return wn, nil
	case "eval":
		var w wireCommand
		if err := json.Unmarshal(raw, &w); err != nil {
			return nil, err
		}
		if len(w.Assignments) == 0 {
			return nil, fmt.Errorf("eval requires at least one assignment")
		}
		en := &EvalNode{Assignments: w.Assignments}
		en.Field = w.Assignments[0].Field
		en.Expr = w.Assignments[0].Expr
		return en, nil
	case "fields":
		var w wireCommand
		if err := json.Unmarshal(raw, &w); err != nil {
			return nil, err
		}
		inc := true
		if w.Include != nil {
			inc = *w.Include
		}
		return &FieldsNode{Include: inc, Fields: w.Columns}, nil
	case "table":
		var w wireCommand
		if err := json.Unmarshal(raw, &w); err != nil {
			return nil, err
		}
		return &TableNode{Fields: w.Columns}, nil
	case "rename":
		var w wireCommand
		if err := json.Unmarshal(raw, &w); err != nil {
			return nil, err
		}
		rn := &RenameNode{Mappings: make(map[string]string), MappingsOrdered: w.Mappings}
		for _, p := range w.Mappings {
			rn.Mappings[p.From] = p.To
		}
		return rn, nil
	case "stats":
		var w wireCommand
		if err := json.Unmarshal(raw, &w); err != nil {
			return nil, err
		}
		return &StatsNode{Aggs: w.Aggs, GroupBy: w.GroupBy}, nil
	case "timechart":
		var w wireCommand
		if err := json.Unmarshal(raw, &w); err != nil {
			return nil, err
		}
		var fn Aggregation
		if w.Agg != nil {
			fn = *w.Agg
		} else {
			fn = Aggregation{Function: "count", Field: "*"}
		}
		return &TimechartNode{Func: fn, Span: w.Span, GroupBy: w.GroupBy}, nil
	case "sort":
		var w wireCommand
		if err := json.Unmarshal(raw, &w); err != nil {
			return nil, err
		}
		return &SortNode{Fields: w.Sort}, nil
	case "head":
		var w wireCommand
		if err := json.Unmarshal(raw, &w); err != nil {
			return nil, err
		}
		return &HeadNode{N: w.N}, nil
	case "tail":
		var w wireCommand
		if err := json.Unmarshal(raw, &w); err != nil {
			return nil, err
		}
		return &TailNode{N: w.N}, nil
	case "dedup":
		var w wireCommand
		if err := json.Unmarshal(raw, &w); err != nil {
			return nil, err
		}
		return &DedupNode{Field: w.Field}, nil
	case "rex":
		var w wireCommand
		if err := json.Unmarshal(raw, &w); err != nil {
			return nil, err
		}
		return &RexNode{Field: w.Field, Pattern: w.Pattern, Rename: w.Alias, Mode: w.Mode}, nil
	case "bin":
		var w wireCommand
		if err := json.Unmarshal(raw, &w); err != nil {
			return nil, err
		}
		return &BinNode{Field: w.Field, Span: w.Span}, nil
	case "lookup":
		var w wireCommand
		if err := json.Unmarshal(raw, &w); err != nil {
			return nil, err
		}
		return &LookupNode{Lookup: w.Lookup, InputField: w.Field, OutputFields: w.OutputFields, Append: w.Append}, nil
	case "eventstats":
		var w wireCommand
		if err := json.Unmarshal(raw, &w); err != nil {
			return nil, err
		}
		return &EventstatsNode{Aggs: w.Aggs, GroupBy: w.GroupBy}, nil
	case "streamstats":
		var w wireCommand
		if err := json.Unmarshal(raw, &w); err != nil {
			return nil, err
		}
		return &StreamstatsNode{Aggs: w.Aggs, GroupBy: w.GroupBy, Window: w.Window}, nil
	case "unsupported":
		var w wireCommand
		if err := json.Unmarshal(raw, &w); err != nil {
			return nil, err
		}
		return &UnsupportedNode{Name: w.Name, Raw: w.Raw}, nil
	default:
		return nil, fmt.Errorf("unknown command type %q", kind)
	}
}

func renamePairs(r *RenameNode) []RenamePair {
	if len(r.MappingsOrdered) > 0 {
		return r.MappingsOrdered
	}
	pairs := make([]RenamePair, 0, len(r.Mappings))
	for from, to := range r.Mappings {
		pairs = append(pairs, RenamePair{From: from, To: to})
	}
	return pairs
}

// conditionsToExpr folds a flat AND-only condition list into a boolean tree.
func conditionsToExpr(cs []Condition) *Expr {
	var leaves []*Expr
	for _, c := range cs {
		leaves = append(leaves, Cmp(c.Field, c.Operator, c.Value))
	}
	if len(leaves) == 0 {
		return nil
	}
	if len(leaves) == 1 {
		return leaves[0]
	}
	return And(leaves...)
}

// exprToConditions flattens a pure AND-of-comparisons tree into the classic
// condition list; returns nil for anything with or/not/in/like/isnull.
func exprToConditions(e *Expr) []Condition {
	if e == nil {
		return nil
	}
	var out []Condition
	var walk func(x *Expr) bool
	walk = func(x *Expr) bool {
		switch x.Kind {
		case "cmp":
			out = append(out, Condition{Field: x.Field, Operator: x.Op, Value: x.Value})
			return true
		case "and":
			for _, a := range x.Args {
				if !walk(a) {
					return false
				}
			}
			return true
		default:
			return false
		}
	}
	if !walk(e) {
		return nil
	}
	return out
}

// ValidationError is one structured validation problem with the offending
// component, so the UI can highlight the exact card.
type ValidationError struct {
	Component string `json:"component"`
	Message   string `json:"message"`
}

// supportedAggs is the aggregate function vocabulary shared by validate, the
// planner and the UI function list.
var supportedAggs = map[string]bool{
	"count": true, "sum": true, "avg": true, "min": true, "max": true,
	"dc": true, "distinct_count": true, "values": true, "list": true,
}

func aggsOf(n Node) []Aggregation {
	switch x := n.(type) {
	case *StatsNode:
		return x.Aggs
	case *EventstatsNode:
		return x.Aggs
	case *StreamstatsNode:
		return x.Aggs
	case *TimechartNode:
		if strings.TrimSpace(x.Func.Function) == "" {
			return nil
		}
		return []Aggregation{x.Func}
	}
	return nil
}

// Validate reports every structural problem that would make a query fail to
// execute. An empty search is allowed (it means "all events").
func (q *Query) Validate() []ValidationError {
	var errs []ValidationError
	add := func(component, msg string) {
		errs = append(errs, ValidationError{Component: component, Message: msg})
	}
	if q == nil || len(q.Commands) == 0 {
		add("query", "the query is empty")
		return errs
	}
	for _, n := range q.Commands {
		component := commandType(n)
		switch x := n.(type) {
		case *SearchNode:
			// An empty search is valid (matches all).
		case *WhereNode:
			if x.Expr == nil && len(x.Conditions) == 0 {
				add("where", "a where command needs an expression")
			}
		case *EvalNode:
			asg := x.Assignments
			if len(asg) == 0 && x.Field != "" {
				asg = []EvalAssignment{{Field: x.Field, Expr: x.Expr}}
			}
			if len(asg) == 0 {
				add("eval", "an eval command needs at least one field=expression")
			}
			for _, a := range asg {
				if strings.TrimSpace(a.Field) == "" {
					add("eval", "an eval assignment is missing a field name")
				}
				if strings.TrimSpace(a.Expr) == "" {
					add("eval", "eval assignment for "+a.Field+" is missing an expression")
				}
			}
		case *StatsNode, *EventstatsNode, *StreamstatsNode:
			if len(aggsOf(n)) == 0 {
				add(component, component+" needs at least one aggregation")
			}
			for _, a := range aggsOf(n) {
				validateAgg(a, component, add)
			}
		case *TimechartNode:
			aggs := aggsOf(n)
			if len(aggs) == 0 {
				add("timechart", "timechart needs an aggregation (e.g. count)")
			}
			for _, a := range aggs {
				validateAgg(a, "timechart", add)
			}
		case *SortNode:
			if len(x.Fields) == 0 {
				add("sort", "sort needs at least one field")
			}
		case *HeadNode:
			if x.N < 0 {
				add("head", "head count cannot be negative")
			}
		case *TailNode:
			if x.N < 0 {
				add("tail", "tail count cannot be negative")
			}
		case *DedupNode:
			if strings.TrimSpace(x.Field) == "" {
				add("dedup", "dedup needs a field")
			}
		case *TableNode:
			if len(x.Fields) == 0 {
				add("table", "table needs at least one column")
			}
		case *FieldsNode:
			if len(x.Fields) == 0 {
				add("fields", "fields needs at least one field")
			}
		case *RenameNode:
			if len(x.Mappings) == 0 && len(x.MappingsOrdered) == 0 {
				add("rename", "rename needs at least one from→to pair")
			}
		case *RexNode:
			if strings.TrimSpace(x.Pattern) == "" {
				add("rex", "rex needs a regular expression")
			}
		case *BinNode:
			if strings.TrimSpace(x.Field) == "" {
				add("bin", "bin needs a field")
			}
		case *UnsupportedNode:
			add("unsupported", x.Name+" is not supported by the visual builder")
		}
	}
	return errs
}

func validateAgg(a Aggregation, component string, add func(string, string)) {
	fn := strings.ToLower(strings.TrimSpace(a.Function))
	if fn == "" {
		add(component, "an aggregation is missing a function")
		return
	}
	if !supportedAggs[fn] {
		add(component, "unsupported aggregation function: "+a.Function)
		return
	}
	if strings.TrimSpace(a.Field) == "" && fn != "count" {
		add(component, fn+"() needs a field")
	}
}

// EnsureSearchFirst guarantees the pipeline invariant that commands[0] is a
// search node, inserting an empty one when the builder produced a query that
// starts elsewhere.
func (q *Query) EnsureSearchFirst() {
	if q == nil {
		return
	}
	if len(q.Commands) > 0 {
		if _, ok := q.Commands[0].(*SearchNode); ok {
			return
		}
	}
	cmds := make([]Node, 0, len(q.Commands)+1)
	cmds = append(cmds, &SearchNode{})
	cmds = append(cmds, q.Commands...)
	q.Commands = cmds
}
