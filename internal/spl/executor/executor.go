package executor

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"quetzalog/internal/spl/ast"
	"quetzalog/internal/spl/parser"
	"quetzalog/internal/spl/planner"
)

// EvalEvaluator handles eval expression evaluation and transformations.
type EvalEvaluator struct{}

// NewEvalEvaluator creates a new EvalEvaluator.
func NewEvalEvaluator() (*EvalEvaluator, error) {
	return &EvalEvaluator{}, nil
}

type Executor struct {
	db *sql.DB
}

func New(db *sql.DB) *Executor {
	return &Executor{db: db}
}

func (e *Executor) Execute(ctx context.Context, query *ast.Query) ([]map[string]any, []string, error) {
	if query == nil {
		return nil, nil, fmt.Errorf("nil query")
	}

	plan := planner.PlanQuery(query)
	sqlQuery, err := planner.BuildSQL(plan)
	if err != nil {
		return nil, nil, fmt.Errorf("build SQL failed: %w", err)
	}

	rows, err := e.db.QueryContext(ctx, sqlQuery, plan.Args...)
	if err != nil {
		return nil, nil, fmt.Errorf("query execution failed: %w", err)
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, nil, fmt.Errorf("get columns failed: %w", err)
	}

	// Resolve renames
	renameMap := planner.ColumnMappings(query.Commands)

	// Normalize columns with renames
	renamedCols := make([]string, len(columns))
	for i, col := range columns {
		if new, ok := renameMap[col]; ok {
			renamedCols[i] = new
		} else {
			renamedCols[i] = col
		}
	}

	var results []map[string]any

	// The column set is fixed for the whole result set, so the scan targets
	// are built once and refilled by Scan on every row.
	vals := make([]any, len(columns))
	valPtrs := make([]any, len(columns))
	for i := range vals {
		valPtrs[i] = &vals[i]
	}

	for rows.Next() {
		if err := rows.Scan(valPtrs...); err != nil {
			return nil, nil, fmt.Errorf("scan row failed: %w", err)
		}

		row := make(map[string]any, len(renamedCols))
		for i, col := range renamedCols {
			v := vals[i]
			// Convert []byte to string for SQLite
			if b, ok := v.([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = v
			}
		}

		// Apply eval transformations
		row = e.applyEval(row, query.Commands)

		results = append(results, row)
	}

	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("row iteration error: %w", err)
	}

	return results, renamedCols, nil
}

func (e *Executor) ExecuteString(ctx context.Context, input string) ([]map[string]any, []string, error) {
	p, err := parser.New(input)
	if err != nil {
		return nil, nil, fmt.Errorf("parse failed: %w", err)
	}

	query, err := p.Parse()
	if err != nil {
		return nil, nil, fmt.Errorf("parse failed: %w", err)
	}

	return e.Execute(ctx, query)
}

func (e *Executor) applyEval(row map[string]any, commands []ast.Node) map[string]any {
	for _, cmd := range commands {
		if n, ok := cmd.(*ast.EvalNode); ok {
			row[n.Field] = e.evaluateExpr(n.Expr, row)
		}
	}
	return row
}

func (e *Executor) evaluateExpr(expr string, row map[string]any) any {
	ev := &EvalEvaluator{}
	return ev.EvalExpr(row, expr)
}

// TransformEval applies eval expressions to a batch of events.
func (e *EvalEvaluator) TransformEval(events []map[string]any, nodes []ast.Node) {
	for _, node := range nodes {
		eval, ok := node.(*ast.EvalNode)
		if !ok {
			continue
		}
		for i := range events {
			events[i][eval.Field] = e.EvalExpr(events[i], eval.Expr)
		}
	}
}

// EvalExpr evaluates an expression against event data.
func (e *EvalEvaluator) EvalExpr(event map[string]any, expr string) any {
	// Strip surrounding quotes from string literals
	if (strings.HasPrefix(expr, `"`) && strings.HasSuffix(expr, `"`)) ||
		(strings.HasPrefix(expr, `'`) && strings.HasSuffix(expr, `'`)) {
		return expr[1 : len(expr)-1]
	}

	// Check if it's a field reference
	if val, ok := event[expr]; ok {
		return val
	}

	// Try to parse as a number
	if num, err := strconv.ParseFloat(expr, 64); err == nil {
		return num
	}

	// Check for arithmetic: field * num, field / num, field + num, field - num
	if match := tryArithmetic(expr); match != nil {
		if fieldVal, ok := event[match.field]; ok {
			if f, ok := fieldVal.(float64); ok {
				return applyArith(f, match.op, match.operand)
			}
			if i, ok := fieldVal.(int); ok {
				return applyArith(float64(i), match.op, match.operand)
			}
		}
	}

	// Default: return as literal string
	return expr
}

type arithMatch struct {
	field   string
	op      string
	operand float64
}

var arithPattern = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*)\s*([+\-*/])\s*([0-9.]+)$`)

func tryArithmetic(expr string) *arithMatch {
	matches := arithPattern.FindStringSubmatch(expr)
	if matches == nil {
		return nil
	}
	operand, err := strconv.ParseFloat(matches[3], 64)
	if err != nil {
		return nil
	}
	return &arithMatch{
		field:   matches[1],
		op:      matches[2],
		operand: operand,
	}
}

func applyArith(a float64, op string, b float64) float64 {
	switch op {
	case "+":
		return a + b
	case "-":
		return a - b
	case "*":
		return a * b
	case "/":
		if b == 0 {
			return 0
		}
		return a / b
	default:
		return a
	}
}

// TransformRex extracts named groups from a regex pattern into event fields.
func (e *EvalEvaluator) TransformRex(event map[string]any, node *ast.RexNode) error {
	if node.Pattern == "" {
		return nil
	}

	re, err := regexp.Compile(node.Pattern)
	if err != nil {
		return fmt.Errorf("compile regex: %w", err)
	}

	field := node.Field
	if field == "" {
		field = "message"
	}

	input, ok := event[field].(string)
	if !ok {
		input = fmt.Sprintf("%v", event[field])
	}

	matches := re.FindStringSubmatch(input)
	if matches == nil {
		return nil
	}

	for i, name := range re.SubexpNames() {
		if i == 0 {
			continue
		}
		if name == "" {
			continue
		}
		value := matches[i]
		if node.Mode == "multimatch" {
			existing := event[name]
			if existing == nil {
				event[name] = []string{value}
			} else if arr, ok := existing.([]string); ok {
				event[name] = append(arr, value)
			} else {
				event[name] = []string{existing.(string), value}
			}
		} else {
			event[name] = value
		}
	}

	if node.Rename != "" && re.SubexpNames()[1] != node.Rename {
		for i, name := range re.SubexpNames() {
			if i == 0 || name == "" {
				continue
			}
			if val, ok := event[name]; ok {
				event[node.Rename] = val
				delete(event, name)
				break
			}
		}
	}

	return nil
}
