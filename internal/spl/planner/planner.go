// Package planner lowers an ast.Query into a parameterized SQLite plan. Field
// names are resolved against the canonical Quetzalog schema: known columns map
// directly, `index` fans out across source_type/source/attribute, and any other
// field maps to a JSON path over the attributes column. All user values are
// bound as parameters (never concatenated), and identifiers are whitelist-checked
// to keep SQL injection impossible via field names.
package planner

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"quetzalog/internal/spl/ast"
)

// canonical columns of the events table (lowercased name -> column).
var columns = map[string]string{
	"id": "id", "timestamp": "timestamp", "time": "timestamp", "_time": "timestamp",
	"received_at": "received_at", "source": "source", "sourcename": "source",
	"source_type": "source_type", "sourcetype": "source_type", "host": "host",
	"ip": "ip", "service": "service", "application": "application", "severity": "severity",
	"sev": "severity", "message": "message", "event_type": "event_type", "eventtype": "event_type",
	"category": "category", "action": "action", "outcome": "outcome", "user": "user",
	"username": "user", "user_id": "user_id", "process": "process", "process_id": "process_id",
	"parent_pid": "parent_pid", "file_path": "file_path", "destination_ip": "destination_ip",
	"dest_ip": "destination_ip", "dst_ip": "destination_ip", "destination_port": "destination_port",
	"dest_port": "destination_port", "source_ip": "source_ip", "src_ip": "source_ip",
	"sourceip": "source_ip", "source_port": "source_port", "src_port": "source_port",
	"raw": "raw", "raw_format": "raw_format", "trace_id": "trace_id", "span_id": "span_id",
}

var attrKeyRe = regexp.MustCompile(`^[A-Za-z0-9_\-]+$`)
var ftsTokenRe = regexp.MustCompile(`[[:alnum:]_]+`)

// FieldKind classifies a resolved field.
const (
	fldColumn = iota
	fldAttr
	fldIndex
	fldUnknown
)

func resolveField(field string) (canonical string, kind int) {
	l := strings.ToLower(strings.TrimSpace(field))
	if l == "" {
		return "", fldUnknown
	}
	if l == "index" {
		return "index", fldIndex
	}
	if c, ok := columns[l]; ok {
		return c, fldColumn
	}
	if attrKeyRe.MatchString(field) {
		return field, fldAttr
	}
	return field, fldUnknown
}

// Options controls row/aggregation planning.
type Options struct {
	Earliest time.Time
	Latest   time.Time
	Limit    int
	Offset   int
}

// Plan is a resolved SQL statement plus bound arguments.
type Plan struct {
	SQL           string
	Args          []any
	OutputColumns []string
	IsAggregation bool
	Err           error
}

// ColumnSQL returns a SQL expression for a field plus any bound args it needs
// (equality binds the raw value; ordering compares cast to REAL).
func ColumnSQL(field, op string, value string) (string, []any, error) {
	canonical, kind := resolveField(field)
	switch kind {
	case fldIndex:
		return indexPredicate(op, value)
	case fldColumn:
		return canonical + " " + sqlOp(op) + " ?", []any{coerce(op, value)}, nil
	case fldAttr:
		path := fmt.Sprintf(`$."%s"`, canonical)
		if isEquality(op) {
			return fmt.Sprintf(`CAST(json_extract(attributes, '%s') AS TEXT) %s ?`, path, sqlOp(op)),
				[]any{value}, nil
		}
		return fmt.Sprintf(`CAST(json_extract(attributes, '%s') AS REAL) %s ?`, path, sqlOp(op)),
			[]any{coerce(op, value)}, nil
	default:
		return "1=0", nil, nil
	}
}

func indexPredicate(op, value string) (string, []any, error) {
	if !isEquality(op) {
		// non-equality index comparison: treat as attribute compare on "index".
		return fmt.Sprintf(`CAST(json_extract(attributes, '$."index"') AS REAL) %s ?`, sqlOp(op)),
			[]any{coerce(op, value)}, nil
	}
	neg := ""
	if op == "!=" {
		neg = "NOT "
	}
	core := "(source_type = ? OR source = ? OR CAST(json_extract(attributes, '$.\"index\"') AS TEXT) = ?)"
	return neg + core, []any{value, value, value}, nil
}

func isEquality(op string) bool { return op == "=" || op == "!=" || op == "==" }

// DistinctExpr returns a SQL expression usable in a SELECT DISTINCT for the given
// field, plus whether the field resolves to a real column or an attribute. It is
// used by the builder metadata endpoints to enumerate values without hardcoding any
// vocabulary. The returned expression is safe to embed (never derived from user text
// verbatim: attributes are passed through the identifier whitelist).
func DistinctExpr(field string) (expr string, isAttr bool, ok bool) {
	canonical, kind := resolveField(field)
	switch kind {
	case fldColumn:
		return canonical, false, true
	case fldAttr:
		return fmt.Sprintf(`CAST(json_extract(attributes, '$."%s"') AS TEXT)`, canonical), true, true
	case fldIndex:
		return `CAST(json_extract(attributes, '$."index"') AS TEXT)`, true, true
	default:
		return "", false, false
	}
}

// IsAttributeField reports whether the given field name resolves to a JSON
// attribute (i.e. is not one of the canonical event columns).
func IsAttributeField(field string) bool {
	_, kind := resolveField(field)
	return kind == fldAttr
}

// ColumnOrderExpr returns a SQL expression usable in ORDER BY for the given
// field, plus whether the field resolves to something the database can order by
// (a real column or a numeric/text attribute). Computed/unknown fields return
// ok=false so the caller can fall back to in-process sorting.
func ColumnOrderExpr(field string) (expr string, ok bool) {
	canonical, kind := resolveField(field)
	switch kind {
	case fldColumn:
		return canonical, true
	case fldAttr:
		return fmt.Sprintf(`CAST(json_extract(attributes, '$."%s"') AS TEXT)`, canonical), true
	case fldIndex:
		return `CAST(json_extract(attributes, '$."index"') AS TEXT)`, true
	default:
		return "", false
	}
}

// CanonicalColumns lists the canonical event columns the builder may surface for
// pickers, derived from the planner's own field map (never hardcoded elsewhere).
func CanonicalColumns() []string {
	set := map[string]bool{}
	for _, c := range columns {
		set[c] = true
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	return out
}

func sqlOp(op string) string {
	switch op {
	case "=", "==":
		return "="
	case "!=":
		return "!="
	case "<":
		return "<"
	case "<=":
		return "<="
	case ">":
		return ">"
	case ">=":
		return ">="
	}
	return "="
}

func coerce(op, value string) any {
	if isEquality(op) {
		return value
	}
	if f, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
		return f
	}
	return value
}

// ExprToSQL converts a boolean expression into a SQL WHERE fragment.
func ExprToSQL(e *ast.Expr, args *[]any) (string, error) {
	if e == nil {
		return "1=1", nil
	}
	switch e.Kind {
	case "and":
		return joinLogical(e.Args, " AND ", args)
	case "or":
		return joinLogical(e.Args, " OR ", args)
	case "not":
		inner, err := ExprToSQL(e.Arg, args)
		if err != nil {
			return "", err
		}
		return "NOT (" + inner + ")", nil
	case "cmp":
		expr, bound, err := ColumnSQL(e.Field, e.Op, e.Value)
		if err != nil {
			return "", err
		}
		*args = append(*args, bound...)
		return expr, nil
	case "in":
		return inPredicate(e, args)
	case "isnull":
		canonical, kind := resolveField(e.Field)
		switch kind {
		case fldColumn:
			return nullTest(canonical, e.Negate), nil
		case fldAttr:
			return nullTest(fmt.Sprintf(`json_extract(attributes, '$."%s"')`, canonical), e.Negate), nil
		default:
			return "1=0", nil
		}
	case "like":
		return likePredicate(e, args)
	case "text":
		return textPredicate(e.Value, args)
	default:
		return "", fmt.Errorf("unsupported expression kind %q", e.Kind)
	}
}

func joinLogical(args []*ast.Expr, sep string, out *[]any) (string, error) {
	if len(args) == 0 {
		return "1=1", nil
	}
	parts := make([]string, 0, len(args))
	for _, a := range args {
		s, err := ExprToSQL(a, out)
		if err != nil {
			return "", err
		}
		parts = append(parts, s)
	}
	joined := strings.Join(parts, sep)
	if len(parts) > 1 {
		return "(" + joined + ")", nil
	}
	return joined, nil
}

func inPredicate(e *ast.Expr, out *[]any) (string, error) {
	if len(e.Values) == 0 {
		if e.Negate {
			return "1=1", nil
		}
		return "1=0", nil
	}
	placeholders := make([]string, len(e.Values))
	for i := range placeholders {
		placeholders[i] = "?"
	}
	canonical, kind := resolveField(e.Field)
	var side string
	switch kind {
	case fldColumn:
		side = canonical
	case fldAttr:
		side = fmt.Sprintf(`CAST(json_extract(attributes, '$."%s"') AS TEXT)`, canonical)
	default:
		return "1=0", nil
	}
	for _, v := range e.Values {
		*out = append(*out, v)
	}
	neg := ""
	if e.Negate {
		neg = "NOT "
	}
	return fmt.Sprintf("%s %sIN (%s)", side, neg, strings.Join(placeholders, ", ")), nil
}

func likePredicate(e *ast.Expr, out *[]any) (string, error) {
	canonical, kind := resolveField(e.Field)
	var side string
	switch kind {
	case fldColumn:
		side = canonical
	case fldAttr:
		side = fmt.Sprintf(`CAST(json_extract(attributes, '$."%s"') AS TEXT)`, canonical)
	default:
		return "1=0", nil
	}
	*out = append(*out, e.Pattern)
	if e.Negate {
		return side + " NOT LIKE ?", nil
	}
	return side + " LIKE ?", nil
}

func nullTest(expr string, neg bool) string {
	if neg {
		return expr + " IS NOT NULL"
	}
	return expr + " IS NULL"
}

func textPredicate(term string, out *[]any) (string, error) {
	match := sanitizeFTS(term)
	*out = append(*out, match)
	return "rowid IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)", nil
}

func sanitizeFTS(q string) string {
	tokens := ftsTokenRe.FindAllString(q, -1)
	if len(tokens) == 0 {
		return `""`
	}
	var b strings.Builder
	b.Grow(len(q) + 4*len(tokens))
	for i, tok := range tokens {
		if i > 0 {
			b.WriteString(" AND ")
		}
		b.WriteByte('"')
		b.WriteString(tok)
		b.WriteByte('"')
	}
	return b.String()
}

// BuildWhere assembles the WHERE clause (search + where commands + time range).
func BuildWhere(q *ast.Query, opts Options, args *[]any) (string, error) {
	var clauses []string
	add := func(s string) {
		if s != "" && s != "1=1" {
			clauses = append(clauses, s)
		}
	}
	if s := q.Search(); s != nil {
		if s.Expr != nil {
			sql, err := ExprToSQL(s.Expr, args)
			if err != nil {
				return "", err
			}
			add(sql)
		} else {
			sql, err := exprFromSearchFields(s, args)
			if err != nil {
				return "", err
			}
			add(sql)
		}
	}
	for _, c := range q.Commands {
		if w, ok := c.(*ast.WhereNode); ok {
			e := w.Expr
			if e == nil {
				e = conditionsToExpr(w.Conditions)
			}
			sql, err := ExprToSQL(e, args)
			if err != nil {
				return "", err
			}
			add(sql)
		}
	}
	if !opts.Earliest.IsZero() {
		add("timestamp >= ?")
		*args = append(*args, opts.Earliest.UTC())
	}
	if !opts.Latest.IsZero() {
		add("timestamp <= ?")
		*args = append(*args, opts.Latest.UTC())
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return "WHERE " + strings.Join(clauses, " AND "), nil
}

func exprFromSearchFields(s *ast.SearchNode, args *[]any) (string, error) {
	var parts []string
	for k, v := range s.Fields {
		expr, bound, err := ColumnSQL(k, "=", v)
		if err != nil {
			return "", err
		}
		*args = append(*args, bound...)
		parts = append(parts, expr)
	}
	if strings.TrimSpace(s.Text) != "" {
		sql, err := textPredicate(s.Text, args)
		if err != nil {
			return "", err
		}
		parts = append(parts, sql)
	}
	if len(parts) == 0 {
		return "", nil
	}
	return "(" + strings.Join(parts, " AND ") + ")", nil
}

func conditionsToExpr(cs []ast.Condition) *ast.Expr {
	var leaves []*ast.Expr
	for _, c := range cs {
		leaves = append(leaves, ast.Cmp(c.Field, c.Operator, c.Value))
	}
	if len(leaves) == 0 {
		return nil
	}
	if len(leaves) == 1 {
		return leaves[0]
	}
	return ast.And(leaves...)
}

// HasAggregation reports whether the pipeline collapses rows via stats/timechart.
func HasAggregation(q *ast.Query) bool {
	for _, c := range q.Commands {
		switch c.(type) {
		case *ast.StatsNode:
			return true
		case *ast.TimechartNode:
			return true
		}
	}
	return false
}

// AggSQL builds the SELECT + GROUP BY + ORDER BY for a stats/timechart query.
type AggSQL struct {
	Select string
	GroupBy string
	OrderBy string
	Columns []string
	IsTime  bool
}

// BuildAggregate constructs the aggregation clause list.
func BuildAggregate(q *ast.Query) AggSQL {
	var sel []string
	var gb []string
	var cols []string
	isTime := false
	var orderBy string

	for _, c := range q.Commands {
		switch x := c.(type) {
		case *ast.StatsNode:
			for _, a := range x.Aggs {
				expr, alias := aggExpr(a)
				sel = append(sel, expr+" AS "+quoteIdent(alias))
				cols = append(cols, alias)
			}
			for _, g := range x.GroupBy {
				expr, _ := groupExpr(g)
				sel = append(sel, expr+" AS "+quoteIdent(g))
				gb = append(gb, expr)
				cols = append(cols, g)
			}
		case *ast.TimechartNode:
			isTime = true
			sel = append(sel, `datetime(CAST(strftime('%s', timestamp) AS INTEGER) / `+spanSeconds(x.Span)+` * `+spanSeconds(x.Span)+`, 'unixepoch') AS _time`)
			cols = append(cols, "_time")
			expr, alias := aggExpr(x.Func)
			sel = append(sel, expr+" AS "+quoteIdent(alias))
			cols = append(cols, alias)
			gbBucket := `CAST(strftime('%s', timestamp) AS INTEGER) / ` + spanSeconds(x.Span)
			gb = append(gb, gbBucket)
			for _, g := range x.GroupBy {
				expr, _ := groupExpr(g)
				sel = append(sel, expr+" AS "+quoteIdent(g))
				gb = append(gb, expr)
				cols = append(cols, g)
			}
		case *ast.SortNode:
			var parts []string
			for _, f := range x.Fields {
				dir := "ASC"
				if f.Desc {
					dir = "DESC"
				}
				key := f.Field
				// Order by the projected alias when it matches an agg alias/col.
				parts = append(parts, quoteIdent(stripMinus(f.Field))+" "+dir)
				_ = key
			}
			if len(parts) > 0 {
				orderBy = "ORDER BY " + strings.Join(parts, ", ")
			}
		case *ast.HeadNode:
			// handled via limit by caller
		}
	}
	if len(sel) == 0 {
		return AggSQL{}
	}
	a := AggSQL{Select: "SELECT " + strings.Join(sel, ", "), Columns: cols, IsTime: isTime}
	if len(gb) > 0 {
		a.GroupBy = "GROUP BY " + strings.Join(gb, ", ")
	}
	a.OrderBy = orderBy
	return a
}

func aggExpr(a ast.Aggregation) (expr, alias string) {
	fn := strings.ToLower(a.Function)
	field := a.Field
	colExpr := "*"
	if field != "" && field != "*" {
		colExpr = aggColumnSQL(field)
	}
	switch fn {
	case "dc":
		expr = fmt.Sprintf("COUNT(DISTINCT %s)", colExpr)
	case "values", "list":
		// Splunk values()/list() -> JSON array of distinct/all values.
		if fn == "values" {
			expr = fmt.Sprintf("json_group_array(DISTINCT %s)", colExpr)
		} else {
			expr = fmt.Sprintf("json_group_array(%s)", colExpr)
		}
	case "count":
		expr = "COUNT(*)"
	default:
		expr = fmt.Sprintf("%s(%s)", fn, colExpr)
	}
	if a.Alias != "" {
		alias = a.Alias
	} else if fn == "count" && (field == "" || field == "*") {
		alias = "count"
	} else if field == "" || field == "*" {
		alias = fn
	} else {
		alias = fn + "_" + sanitizeIdent(field)
	}
	return expr, alias
}

func aggColumnSQL(field string) string {
	canonical, kind := resolveField(field)
	switch kind {
	case fldColumn:
		return canonical
	case fldAttr, fldIndex:
		return fmt.Sprintf(`CAST(json_extract(attributes, '$."%s"') AS REAL)`, canonical)
	default:
		return "NULL"
	}
}

func groupExpr(field string) (string, string) {
	canonical, kind := resolveField(field)
	switch kind {
	case fldColumn:
		return canonical, field
	case fldAttr, fldIndex:
		return fmt.Sprintf(`CAST(json_extract(attributes, '$."%s"') AS TEXT)`, canonical), field
	default:
		return "NULL", field
	}
}

// RowSelectColumns is the canonical projection used for non-aggregated queries.
var RowSelectColumns = []string{
	"id", "timestamp", "received_at", "source", "source_type", "host", "ip", "service",
	"application", "severity", "message", "event_type", "category", "action", "outcome",
	"user", "user_id", "process", "process_id", "parent_pid", "file_path",
	"destination_ip", "destination_port", "source_ip", "source_port", "raw", "raw_format",
	"trace_id", "span_id", "attributes",
}

func spanSeconds(span string) string {
	span = strings.ToLower(strings.TrimSpace(span))
	if span == "" {
		return "60"
	}
	var num string
	var unit rune
	for _, ch := range span {
		if ch >= '0' && ch <= '9' || ch == '.' {
			num += string(ch)
		} else {
			unit = ch
			break
		}
	}
	f, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return "60"
	}
	mult := float64(1)
	switch unit {
	case 's':
		mult = 1
	case 'm':
		mult = 60
	case 'h':
		mult = 3600
	case 'd':
		mult = 86400
	case 'w':
		mult = 604800
	default:
		mult = 60
	}
	return fmt.Sprintf("%d", int64(f*mult))
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(stripMinus(s), `"`, "") + `"` }
func stripMinus(s string) string { return strings.TrimLeft(s, "-+") }
func sanitizeIdent(s string) string {
	var b strings.Builder
	for _, ch := range s {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' {
			b.WriteRune(ch)
		}
	}
	out := b.String()
	if out == "" {
		return "field"
	}
	return out
}

// BuildRowCount builds a COUNT(*) statement sharing the WHERE clause.
func BuildRowCount(where string) string {
	if where == "" {
		return "SELECT COUNT(*) FROM events"
	}
	return "SELECT COUNT(*) FROM events " + where
}
