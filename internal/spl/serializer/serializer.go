// Package serializer renders an ast.Query back into canonical, valid Splunk SPL.
// It is deterministic (map iteration is sorted) and is the only place that
// produces SPL text from the tree, satisfying the requirement that the UI never
// concatenates SPL directly.
package serializer

import (
	"sort"
	"strings"

	"quetzalog/internal/spl/ast"
	"quetzalog/internal/spl/lexer"
)

// Serialize renders the whole pipeline.
func Serialize(q *ast.Query) string {
	if q == nil {
		return ""
	}
	var parts []string
	for i, n := range q.Commands {
		s := serializeNode(n, i == 0)
		if strings.TrimSpace(s) == "" {
			continue
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, "\n| ")
}

func serializeNode(n ast.Node, first bool) string {
	switch x := n.(type) {
	case *ast.SearchNode:
		s := serializeSearch(x)
		if s == "" && first {
			// Preserve the "pipeline always starts with search" invariant even
			// when the search matches everything.
			return "search"
		}
		return s
	case *ast.UnsupportedNode:
		return strings.TrimSpace(x.Raw)
	case *ast.WhereNode:
		e := x.Expr
		if e == nil {
			e = conditionsToExpr(x.Conditions)
		}
		if e == nil {
			return "where 1=1"
		}
		return "where " + serializeExpr(e, precLeaf)
	case *ast.EvalNode:
		asg := x.Assignments
		if len(asg) == 0 && x.Field != "" {
			asg = []ast.EvalAssignment{{Field: x.Field, Expr: x.Expr}}
		}
		bits := make([]string, 0, len(asg))
		for _, a := range asg {
			bits = append(bits, a.Field+"="+a.Expr)
		}
		return "eval " + strings.Join(bits, ", ")
	case *ast.FieldsNode:
		bits := make([]string, 0, len(x.Fields))
		for _, f := range x.Fields {
			if x.Include {
				bits = append(bits, f)
			} else {
				bits = append(bits, "-"+f)
			}
		}
		return "fields " + strings.Join(bits, ", ")
	case *ast.TableNode:
		return "table " + strings.Join(x.Fields, ", ")
	case *ast.RenameNode:
		pairs := x.MappingsOrdered
		if len(pairs) == 0 {
			keys := make([]string, 0, len(x.Mappings))
			for k := range x.Mappings {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				pairs = append(pairs, ast.RenamePair{From: k, To: x.Mappings[k]})
			}
		}
		bits := make([]string, 0, len(pairs))
		for _, p := range pairs {
			bits = append(bits, p.From+" as "+p.To)
		}
		return "rename " + strings.Join(bits, ", ")
	case *ast.StatsNode:
		return "stats " + serializeAggsBy(x.Aggs, x.GroupBy)
	case *ast.TimechartNode:
		s := "timechart"
		if x.Span != "" {
			s += " span=" + x.Span
		}
		s += " " + serializeOneAgg(x.Func)
		if len(x.GroupBy) > 0 {
			s += " by " + strings.Join(x.GroupBy, ", ")
		}
		return s
	case *ast.SortNode:
		bits := make([]string, 0, len(x.Fields))
		for _, f := range x.Fields {
			if f.Desc {
				bits = append(bits, "-"+f.Field)
			} else {
				bits = append(bits, f.Field)
			}
		}
		return "sort " + strings.Join(bits, ", ")
	case *ast.HeadNode:
		return "head " + itoa(x.N)
	case *ast.TailNode:
		return "tail " + itoa(x.N)
	case *ast.DedupNode:
		return "dedup " + x.Field
	case *ast.RexNode:
		s := "rex"
		if x.Field != "" && x.Field != "_raw" && x.Field != "message" {
			s += " field=" + x.Field
		} else if x.Field != "" {
			s += " field=" + x.Field
		}
		s += " " + lexer.StringLiteral(x.Pattern)
		if x.Rename != "" {
			s += " rename=" + x.Rename
		}
		if x.Mode != "" {
			s += " mode=" + x.Mode
		}
		return s
	case *ast.BinNode:
		s := "bin " + x.Field
		if x.Span != "" {
			s += " span=" + x.Span
		}
		return s
	case *ast.LookupNode:
		s := "lookup " + x.Lookup + " " + x.InputField
		if len(x.OutputFields) > 0 {
			s += " OUTPUT " + strings.Join(x.OutputFields, ", ")
		}
		if x.Append {
			s += " APPEND"
		}
		return s
	case *ast.EventstatsNode:
		return "eventstats " + serializeAggsBy(x.Aggs, x.GroupBy)
	case *ast.StreamstatsNode:
		s := "streamstats"
		if x.Window > 0 {
			s += " window=" + itoa(x.Window)
		}
		s += " " + serializeAggsBy(x.Aggs, x.GroupBy)
		return s
	default:
		return ""
	}
}

func serializeSearch(s *ast.SearchNode) string {
	e := mergeSearchExpr(s)
	if e == nil {
		return ""
	}
	return serializeExpr(e, precLeaf)
}

// mergeSearchExpr reconciles Fields/Text/Expr into a single deterministic tree.
func mergeSearchExpr(s *ast.SearchNode) *ast.Expr {
	var nodes []*ast.Expr
	if s.Expr != nil {
		flattenAnd(s.Expr, &nodes)
	}
	keys := make([]string, 0, len(s.Fields))
	for k := range s.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if exprHasField(nodes, k) {
			continue
		}
		nodes = append(nodes, ast.Cmp(k, "=", s.Fields[k]))
	}
	if strings.TrimSpace(s.Text) != "" && !exprHasTextField(nodes) {
		nodes = append(nodes, &ast.Expr{Kind: "text", Value: s.Text})
	}
	return combineAnd(nodes)
}

func flattenAnd(e *ast.Expr, out *[]*ast.Expr) {
	if e == nil {
		return
	}
	if e.Kind == "and" {
		for _, a := range e.Args {
			flattenAnd(a, out)
		}
		return
	}
	*out = append(*out, e)
}

func combineAnd(nodes []*ast.Expr) *ast.Expr {
	if len(nodes) == 0 {
		return nil
	}
	if len(nodes) == 1 {
		return nodes[0]
	}
	return ast.And(nodes...)
}

func exprHasField(nodes []*ast.Expr, field string) bool {
	for _, n := range nodes {
		if n != nil && n.Kind == "cmp" && n.Field == field {
			return true
		}
	}
	return false
}
func exprHasTextField(nodes []*ast.Expr) bool {
	for _, n := range nodes {
		if n != nil && n.Kind == "text" {
			return true
		}
	}
	return false
}

// Operator precedence for parenthesisation.
const (
	precLeaf = 0
	precAnd  = 1
	precOr   = 2
)

func precedenceOf(e *ast.Expr) int {
	switch e.Kind {
	case "and":
		return precAnd
	case "or":
		return precOr
	default:
		return precLeaf
	}
}

func serializeExpr(e *ast.Expr, parentPrec int) string {
	if e == nil {
		return "1=1"
	}
	switch e.Kind {
	case "and":
		s := serializeJoin(e.Args, " AND ", precAnd)
		return maybeParen(s, precAnd, parentPrec)
	case "or":
		s := serializeJoin(e.Args, " OR ", precOr)
		return maybeParen(s, precOr, parentPrec)
	case "not":
		inner := serializeExpr(e.Arg, precAnd) // NOT binds above AND
		return "NOT " + maybeParen(inner, precLeaf, precAnd+1)
	case "cmp":
		val := valueLiteral(e.Op, e.Value)
		return e.Field + e.Op + val
	case "in":
		return serializeIn(e)
	case "isnull":
		if e.Negate {
			return e.Field + " IS NOT NULL"
		}
		return e.Field + " IS NULL"
	case "like":
		if e.Negate {
			return e.Field + " NOT LIKE " + lexer.StringLiteral(e.Pattern)
		}
		return e.Field + " LIKE " + lexer.StringLiteral(e.Pattern)
	case "text":
		return quoteFreeText(e.Value)
	default:
		return ""
	}
}

func serializeJoin(args []*ast.Expr, sep string, myPrec int) string {
	parts := make([]string, 0, len(args))
	for _, a := range args {
		parts = append(parts, serializeExpr(a, myPrec))
	}
	return strings.Join(parts, sep)
}

func maybeParen(s string, myPrec, parentPrec int) string {
	if myPrec > parentPrec {
		return "(" + s + ")"
	}
	return s
}

func serializeIn(e *ast.Expr) string {
	quoted := make([]string, 0, len(e.Values))
	for _, v := range e.Values {
		quoted = append(quoted, valueLiteral("=", v))
	}
	if e.Negate {
		return e.Field + " NOT IN (" + strings.Join(quoted, ", ") + ")"
	}
	return e.Field + " IN (" + strings.Join(quoted, ", ") + ")"
}

func conditionsToExpr(cs []ast.Condition) *ast.Expr {
	var leaves []*ast.Expr
	for _, c := range cs {
		leaves = append(leaves, ast.Cmp(c.Field, c.Operator, c.Value))
	}
	return combineAnd(leaves)
}

func serializeOneAgg(a ast.Aggregation) string {
	s := a.Function
	if a.Function == "count" && (a.Field == "" || a.Field == "*") {
		s = "count"
	} else if a.Field != "" && a.Field != "*" {
		s = a.Function + "(" + a.Field + ")"
	}
	if a.Alias != "" {
		s += " as " + a.Alias
	}
	return s
}

func serializeAggsBy(aggs []ast.Aggregation, groupBy []string) string {
	bits := make([]string, 0, len(aggs))
	for _, a := range aggs {
		bits = append(bits, serializeOneAgg(a))
	}
	s := strings.Join(bits, ", ")
	if len(groupBy) > 0 {
		s += " by " + strings.Join(groupBy, ", ")
	}
	return s
}

// valueLiteral decides quoting for a comparison/in value.
func valueLiteral(op, v string) string {
	if needsQuote(v) {
		return lexer.StringLiteral(v)
	}
	return v
}

func quoteFreeText(v string) string {
	if v == "" {
		return `""`
	}
	if needsQuote(v) {
		return lexer.StringLiteral(v)
	}
	return v
}

func needsQuote(v string) bool {
	if v == "" {
		return true
	}
	if isNumeric(v) {
		return false
	}
	if v == "*" {
		return false
	}
	for _, ch := range v {
		if isIdentSafe(ch) {
			continue
		}
		return true // contains a character that needs quoting
	}
	return false
}

func isIdentSafe(ch rune) bool {
	switch {
	case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9':
		return true
	}
	switch ch {
	case '_', '.', '-', '/', ':', '@', '*', '?':
		return true
	}
	return false
}

func isNumeric(v string) bool {
	if v == "" {
		return false
	}
	i := 0
	if v[0] == '+' || v[0] == '-' {
		i = 1
	}
	dot := false
	digits := 0
	for ; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c == '.':
			if dot {
				return false
			}
			dot = true
		default:
			return false
		}
	}
	return digits > 0
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
