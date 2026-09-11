// Package executor runs a parsed SPL query against the events table through a
// single pipeline shared by the API preview and the search endpoint. SQL is
// produced by the planner (parameterized); row-level commands (eval, rex, sort,
// head, tail, dedup, fields, table, rename, eventstats, streamstats) are applied
// in-process over the projected result set.
package executor

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"quetzalog/internal/spl/ast"
	"quetzalog/internal/spl/parser"
	"quetzalog/internal/spl/planner"
)

// Result is the outcome of executing a query.
type Result struct {
	Columns     []string
	Rows        []map[string]any
	Count       int
	ExecutionMS int64
	RowsScanned int
}

// RunOptions bounds a single execution.
type RunOptions struct {
	Limit    int
	Offset   int
	Earliest time.Time
	Latest   time.Time
	Columns  []string // optional explicit projection (overrides default)
}

// MaxResultRows caps any single execution to a safe size.
const MaxResultRows = 50000

// Executor executes SPL.
type Executor struct {
	db *sql.DB
}

// New constructs an executor.
func New(db *sql.DB) *Executor { return &Executor{db: db} }

// Execute runs a parsed query (legacy entrypoint used by the SPL facade).
func (e *Executor) Execute(ctx context.Context, query *ast.Query) ([]map[string]any, []string, error) {
	res, err := RunQuery(ctx, e.db, query, RunOptions{})
	if err != nil {
		return nil, nil, err
	}
	return res.Rows, res.Columns, nil
}

// ExecuteString parses and runs a query string.
func (e *Executor) ExecuteString(ctx context.Context, input string) ([]map[string]any, []string, error) {
	res, err := Run(ctx, e.db, input, RunOptions{})
	if err != nil {
		return nil, nil, err
	}
	return res.Rows, res.Columns, nil
}

// Run parses and executes an SPL string with the given bounds.
func Run(ctx context.Context, db *sql.DB, input string, opts RunOptions) (*Result, error) {
	p, err := parser.New(input)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ast.ErrInvalidQuery, err)
	}
	q, err := p.Parse()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ast.ErrInvalidQuery, err)
	}
	return RunQuery(ctx, db, q, opts)
}

// RunQuery executes a parsed query.
func RunQuery(ctx context.Context, db *sql.DB, q *ast.Query, opts RunOptions) (*Result, error) {
	if q == nil {
		return nil, fmt.Errorf("%w: nil query", ast.ErrInvalidQuery)
	}
	if names := q.UnsupportedCommands(); len(names) > 0 {
		return nil, fmt.Errorf("%w: unsupported SPL command: %s", ast.ErrInvalidQuery, strings.Join(names, ", "))
	}
	start := time.Now()
	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > MaxResultRows {
		limit = MaxResultRows
	}
	if opts.Offset < 0 {
		opts.Offset = 0
	}

	var args []any
	where, err := planner.BuildWhere(q, planner.Options{Earliest: opts.Earliest, Latest: opts.Latest}, &args)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ast.ErrInvalidQuery, err)
	}

	var res *Result
	if planner.HasAggregation(q) {
		res, err = runAggregate(ctx, db, q, where, args, limit, opts)
	} else {
		res, err = runRows(ctx, db, q, where, args, limit, opts)
	}
	if err != nil {
		return nil, err
	}
	res.ExecutionMS = time.Since(start).Milliseconds()
	return res, nil
}

func runRows(ctx context.Context, db *sql.DB, q *ast.Query, where string, args []any, limit int, opts RunOptions) (*Result, error) {
	cols := strings.Join(planner.RowSelectColumns, ", ")
	// When an explicit sort keys on database-resolvable fields we can order in
	// SQL and safely push head as LIMIT; otherwise we fetch the window and sort
	// in-process (computed/alias fields cannot be ordered by SQLite).
	orderBy, sortInSQL := buildRowOrder(q)
	sqlLimit := clampLimit(opts.Limit)
	if sortInSQL {
		sqlLimit = clampLimit(headN(q, opts.Limit))
	}
	sqlStr := "SELECT " + cols + " FROM events"
	if where != "" {
		sqlStr += " " + where
	}
	sqlStr += " " + orderBy
	sqlStr += fmt.Sprintf(" LIMIT %d OFFSET %d", sqlLimit, opts.Offset)

	rows, err := db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()
	colNames, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	dataSet, err := scanRows(rows, colNames)
	if err != nil {
		return nil, err
	}

	// Total count (before in-process head/tail/sort) for the row pipeline.
	total := 0
	if _, ok := projectionColumns(q); !ok {
		var cnt int
		countSQL := planner.BuildRowCount(where)
		if err := db.QueryRowContext(ctx, countSQL, args...).Scan(&cnt); err != nil {
			total = len(dataSet)
		} else {
			total = cnt
		}
	} else {
		total = len(dataSet)
	}

	// Decode attribute JSON into each row so attribute/computed fields resolve.
	for _, r := range dataSet {
		decodeAttributes(r)
	}

	applyPipeline(q, dataSet)
	applySort(q, dataSet)
	dataSet = applyDedup(q, dataSet)

	outCols, want := projectionColumns(q)
	if !want {
		outCols = defaultColumns()
	}
	outCols = applyRename(q, dataSet, outCols)
	finalRows := project(dataSet, outCols)

	// head/tail already partly enforced in SQL LIMIT; enforce again post-sort.
	finalRows = applyHeadTail(q, finalRows)

	return &Result{Columns: outCols, Rows: finalRows, Count: total, RowsScanned: len(dataSet)}, nil
}

func runAggregate(ctx context.Context, db *sql.DB, q *ast.Query, where string, args []any, limit int, opts RunOptions) (*Result, error) {
	agg := planner.BuildAggregate(q)
	if agg.Select == "" {
		return &Result{Rows: []map[string]any{}, Count: 0}, nil
	}
	sqlStr := agg.Select + " FROM events"
	if where != "" {
		sqlStr += " " + where
	}
	if agg.GroupBy != "" {
		sqlStr += " " + agg.GroupBy
	}
	if agg.OrderBy != "" {
		sqlStr += " " + agg.OrderBy
	}
	sqlStr += fmt.Sprintf(" LIMIT %d", clampLimit(headN(q, limit)))

	rows, err := db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, fmt.Errorf("aggregate query: %w", err)
	}
	defer rows.Close()
	colNames, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	dataSet, err := scanRows(rows, colNames)
	if err != nil {
		return nil, err
	}
	// Only post-process non-collapsing commands that run AFTER the aggregation.
	applyPostAggPipeline(q, dataSet)
	applySort(q, dataSet)
	dataSet = applyDedup(q, dataSet)

	outCols := agg.Columns
	if proj, ok := projectionColumns(q); ok {
		outCols = proj
	}
	outCols = applyRename(q, dataSet, outCols)
	finalRows := project(dataSet, outCols)
	finalRows = applyHeadTail(q, finalRows)
	return &Result{Columns: outCols, Rows: finalRows, Count: len(finalRows), RowsScanned: len(dataSet)}, nil
}

// ───────────────────────────── helpers ───────────────────────────────────

func scanRows(rows *sql.Rows, cols []string) ([]map[string]any, error) {
	var out []map[string]any
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		m := make(map[string]any, len(cols))
		for i, c := range cols {
			m[c] = normalize(vals[i])
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func normalize(v any) any {
	switch x := v.(type) {
	case []byte:
		return string(x)
	case int64:
		if x >= -2147483648 && x <= 2147483647 {
			return int(x)
		}
		return x
	case nil:
		return nil
	default:
		return v
	}
}

func decodeAttributes(r map[string]any) {
	raw, ok := r["attributes"].(string)
	if !ok || raw == "" {
		return
	}
	var attrs map[string]any
	if err := json.Unmarshal([]byte(raw), &attrs); err != nil {
		return
	}
	for k, v := range attrs {
		if _, exists := r[k]; !exists {
			r[k] = normalize(v)
		}
	}
}

func applyPipeline(q *ast.Query, rows []map[string]any) {
	ev := &EvalEvaluator{}
	for _, c := range q.Commands {
		switch x := c.(type) {
		case *ast.EvalNode:
			ev.TransformEval(rows, []ast.Node{x})
		case *ast.RexNode:
			for _, r := range rows {
				_ = ev.TransformRex(r, x)
			}
		case *ast.EventstatsNode:
			applyEventstats(x, rows)
		case *ast.StreamstatsNode:
			applyStreamstats(x, rows)
		}
	}
}

// applyPostAggPipeline applies row-level commands that operate on aggregated rows.
func applyPostAggPipeline(q *ast.Query, rows []map[string]any) {
	ev := &EvalEvaluator{}
	for _, c := range q.Commands {
		switch x := c.(type) {
		case *ast.EvalNode:
			ev.TransformEval(rows, []ast.Node{x})
		case *ast.WhereNode:
			applyWherePost(x, rows)
		}
	}
}

func applyWherePost(w *ast.WhereNode, rows []map[string]any) []map[string]any {
	e := w.Expr
	if e == nil {
		return rows
	}
	ev := &EvalEvaluator{}
	keep := rows[:0]
	for _, r := range rows {
		if evalExprBool(ev, r, e) {
			keep = append(keep, r)
		}
	}
	return keep
}

func evalExprBool(ev *EvalEvaluator, row map[string]any, e *ast.Expr) bool {
	switch e.Kind {
	case "and":
		for _, a := range e.Args {
			if !evalExprBool(ev, row, a) {
				return false
			}
		}
		return true
	case "or":
		for _, a := range e.Args {
			if evalExprBool(ev, row, a) {
				return true
			}
		}
		return false
	case "not":
		return !evalExprBool(ev, row, e.Arg)
	case "cmp":
		got := fmt.Sprintf("%v", row[e.Field])
		return matchOp(e.Op, got, e.Value)
	case "isnull":
		v, ok := row[e.Field]
		isNull := !ok || v == nil || v == ""
		if e.Negate {
			return !isNull
		}
		return isNull
	default:
		return true
	}
}

func matchOp(op, got, want string) bool {
	switch op {
	case "=", "==":
		return got == want
	case "!=":
		return got != want
	case "<", "<=", ">", ">=":
		gf, _ := strconv.ParseFloat(got, 64)
		wf, _ := strconv.ParseFloat(want, 64)
		switch op {
		case "<":
			return gf < wf
		case "<=":
			return gf <= wf
		case ">":
			return gf > wf
		case ">=":
			return gf >= wf
		}
	}
	return true
}

func applyEventstats(x *ast.EventstatsNode, rows []map[string]any) {
	for _, agg := range x.Aggs {
		if len(x.GroupBy) == 0 {
			val := aggregateAll(agg, rows)
			for _, r := range rows {
				r[aggName(agg)] = val
			}
		} else {
			groups := map[string][]map[string]any{}
			order := []string{}
			for _, r := range rows {
				key := groupKey(r, x.GroupBy)
				if _, ok := groups[key]; !ok {
					order = append(order, key)
				}
				groups[key] = append(groups[key], r)
			}
			for _, k := range order {
				val := aggregateAll(agg, groups[k])
				for _, r := range groups[k] {
					r[aggName(agg)] = val
				}
			}
		}
	}
}

func applyStreamstats(x *ast.StreamstatsNode, rows []map[string]any) {
	// Running aggregate within each group; window caps the lookback size.
	groups := map[string][]int{}
	order := []string{}
	for i, r := range rows {
		key := groupKey(r, x.GroupBy)
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], i)
	}
	for _, agg := range x.Aggs {
		for _, key := range order {
			idxs := groups[key]
			var running []map[string]any
			for _, i := range idxs {
				running = append(running, rows[i])
				if x.Window > 0 && len(running) > x.Window {
					running = running[len(running)-x.Window:]
				}
				rows[i][aggName(agg)] = aggregateAll(agg, running)
			}
		}
	}
}

func aggregateAll(agg ast.Aggregation, rows []map[string]any) any {
	fn := strings.ToLower(agg.Function)
	field := agg.Field
	var nums []float64
	var strs []string
	seen := map[string]bool{}
	for _, r := range rows {
		v := r[field]
		if v == nil {
			continue
		}
		s := fmt.Sprintf("%v", v)
		if fn == "count" && (field == "" || field == "*") {
			continue
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			nums = append(nums, f)
		}
		if fn == "values" || fn == "dc" {
			if !seen[s] {
				seen[s] = true
				strs = append(strs, s)
			}
		} else if fn == "list" {
			strs = append(strs, s)
		}
	}
	switch fn {
	case "count":
		if field == "" || field == "*" {
			return len(rows)
		}
		return len(nums)
	case "sum":
		var s float64
		for _, f := range nums {
			s += f
		}
		return s
	case "avg":
		if len(nums) == 0 {
			return 0
		}
		var s float64
		for _, f := range nums {
			s += f
		}
		return s / float64(len(nums))
	case "min":
		if len(nums) == 0 {
			return 0
		}
		m := nums[0]
		for _, f := range nums[1:] {
			if f < m {
				m = f
			}
		}
		return m
	case "max":
		if len(nums) == 0 {
			return 0
		}
		m := nums[0]
		for _, f := range nums[1:] {
			if f > m {
				m = f
			}
		}
		return m
	case "dc":
		return len(seen)
	case "values":
		b, _ := json.Marshal(strs)
		return string(b)
	case "list":
		b, _ := json.Marshal(strs)
		return string(b)
	}
	return nil
}

func aggName(a ast.Aggregation) string {
	if a.Alias != "" {
		return a.Alias
	}
	if a.Function == "count" && (a.Field == "" || a.Field == "*") {
		return "count"
	}
	if a.Field == "" || a.Field == "*" {
		return a.Function
	}
	return a.Function + "_" + a.Field
}

func groupKey(r map[string]any, by []string) string {
	parts := make([]string, len(by))
	for i, b := range by {
		parts[i] = fmt.Sprintf("%v", r[b])
	}
	return strings.Join(parts, "\x1f")
}

func project(rows []map[string]any, cols []string) []map[string]any {
	if len(cols) == 0 {
		return rows
	}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		m := make(map[string]any, len(cols))
		for _, c := range cols {
			m[c] = valueFor(r, c)
		}
		out = append(out, m)
	}
	return out
}

// valueFor resolves a requested projection column (which may be an alias such
// as _time or src_ip, or a raw/attribute/computed field) to a value in the row.
func valueFor(r map[string]any, name string) any {
	l := strings.ToLower(name)
	switch l {
	case "_time", "time":
		if v, ok := r["timestamp"]; ok {
			return v
		}
	}
	if v, ok := r[name]; ok {
		return v
	}
	if v, ok := r[l]; ok {
		return v
	}
	switch l {
	case "src_ip", "sourceip":
		return r["source_ip"]
	case "dst_ip", "dest_ip", "destinationip":
		return r["destination_ip"]
	case "src_port":
		return r["source_port"]
	case "dest_port":
		return r["destination_port"]
	case "sourcetype", "source_type":
		return r["source_type"]
	case "eventtype", "event_type":
		return r["event_type"]
	}
	return nil
}

func applyHeadTail(q *ast.Query, rows []map[string]any) []map[string]any {
	for _, c := range q.Commands {
		switch x := c.(type) {
		case *ast.HeadNode:
			n := x.N
			if n < 0 {
				n = 0
			}
			if n < len(rows) {
				rows = rows[:n]
			}
		case *ast.TailNode:
			n := x.N
			if n < 0 {
				n = 0
			}
			if n < len(rows) {
				rows = rows[len(rows)-n:]
			}
		}
	}
	return rows
}

func projectionColumns(q *ast.Query) ([]string, bool) {
	var cols []string
	found := false
	for _, c := range q.Commands {
		switch x := c.(type) {
		case *ast.TableNode:
			cols = canonicalizeCols(x.Fields)
			found = true
		case *ast.FieldsNode:
			if x.Include {
				cols = canonicalizeCols(x.Fields)
				found = true
			} else if found {
				cols = removeCols(cols, x.Fields)
			} else {
				cols = removeCols(defaultColumns(), x.Fields)
				found = true
			}
		}
	}
	return cols, found
}

func canonicalizeCols(in []string) []string {
	out := make([]string, 0, len(in))
	for _, f := range in {
		if f == "*" {
			continue
		}
		out = append(out, f)
	}
	return out
}

func removeCols(cols, drop []string) []string {
	set := map[string]bool{}
	for _, d := range drop {
		set[strings.ToLower(d)] = true
	}
	out := cols[:0]
	for _, c := range cols {
		if !set[strings.ToLower(c)] {
			out = append(out, c)
		}
	}
	return out
}

func defaultColumns() []string {
	return []string{"id", "timestamp", "source", "severity", "event_type", "host", "message"}
}

func headN(q *ast.Query, fallback int) int {
	n := fallback
	for _, c := range q.Commands {
		switch x := c.(type) {
		case *ast.HeadNode:
			if x.N >= 0 && x.N < n {
				n = x.N
			}
		}
	}
	return n
}

// buildRowOrder derives a SQL ORDER BY clause from an explicit sort command when
// every sort key is database-resolvable. It returns the clause plus whether the
// ordering was expressible in SQL; when false, the caller must sort in-process.
func buildRowOrder(q *ast.Query) (string, bool) {
	var sn *ast.SortNode
	for _, c := range q.Commands {
		if s, ok := c.(*ast.SortNode); ok {
			sn = s
			break
		}
	}
	if sn == nil || len(sn.Fields) == 0 {
		return "ORDER BY timestamp DESC", true
	}
	parts := make([]string, 0, len(sn.Fields))
	for _, f := range sn.Fields {
		expr, ok := planner.ColumnOrderExpr(f.Field)
		if !ok {
			return "ORDER BY timestamp DESC", false
		}
		dir := "ASC"
		if f.Desc {
			dir = "DESC"
		}
		parts = append(parts, expr+" "+dir)
	}
	return "ORDER BY " + strings.Join(parts, ", "), true
}

func clampLimit(n int) int {
	if n < 0 {
		return 0
	}
	if n > MaxResultRows {
		return MaxResultRows
	}
	return n
}

func postCount(q *ast.Query, rows []map[string]any, total int) int {
	for _, c := range q.Commands {
		if _, ok := c.(*ast.SortNode); ok {
			// sorting does not change the total
		}
	}
	return total
}

// ApplyRenamesToColumns is used by callers that want the post-rename view.
func ApplyRenamesToColumns(q *ast.Query, cols []string) []string {
	for _, c := range q.Commands {
		if r, ok := c.(*ast.RenameNode); ok {
			for i, col := range cols {
				if to, found := r.Mappings[col]; found {
					cols[i] = to
				}
			}
		}
	}
	return cols
}

// ───────────────────────── row pipeline commands ────────────────────────
func applySort(q *ast.Query, rows []map[string]any) {
	for _, c := range q.Commands {
		if x, ok := c.(*ast.SortNode); ok {
			// Apply least-significant key first (stable) so the first field wins.
			for i := len(x.Fields) - 1; i >= 0; i-- {
				f := x.Fields[i]
				sortRows(rows, f.Field, f.Desc)
			}
		}
	}
}

func applyDedup(q *ast.Query, rows []map[string]any) []map[string]any {
	for _, c := range q.Commands {
		if x, ok := c.(*ast.DedupNode); ok {
			rows = dedupRows(rows, x.Field)
		}
	}
	return rows
}

func applyRename(q *ast.Query, rows []map[string]any, cols []string) []string {
	mapping := map[string]string{}
	for _, c := range q.Commands {
		if r, ok := c.(*ast.RenameNode); ok {
			for from, to := range r.Mappings {
				mapping[strings.ToLower(from)] = to
			}
		}
	}
	if len(mapping) == 0 {
		return cols
	}
	for _, r := range rows {
		for from, to := range mapping {
			for k, v := range r {
				if strings.ToLower(k) == from {
					r[to] = v
					if k != to {
						delete(r, k)
					}
					break
				}
			}
		}
	}
	out := make([]string, len(cols))
	for i, c := range cols {
		if to, ok := mapping[strings.ToLower(c)]; ok {
			out[i] = to
			continue
		}
		out[i] = c
	}
	return out
}

// dedupRows removes duplicate rows by field keeping first occurrence.
func dedupRows(rows []map[string]any, field string) []map[string]any {
	seen := map[string]bool{}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		k := fmt.Sprintf("%v", valueFor(r, field))
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, r)
	}
	return out
}

// sortRows sorts by a field, descending when desc.
func sortRows(rows []map[string]any, field string, desc bool) {
	sort.SliceStable(rows, func(i, j int) bool {
		a := valueFor(rows[i], field)
		b := valueFor(rows[j], field)
		c := cmpValues(a, b)
		if desc {
			return c > 0
		}
		return c < 0
	})
}

func cmpValues(a, b any) int {
	af, aerr := strconv.ParseFloat(fmt.Sprintf("%v", a), 64)
	bf, berr := strconv.ParseFloat(fmt.Sprintf("%v", b), 64)
	if aerr == nil && berr == nil {
		switch {
		case af < bf:
			return -1
		case af > bf:
			return 1
		}
		return 0
	}
	return strings.Compare(fmt.Sprintf("%v", a), fmt.Sprintf("%v", b))
}
