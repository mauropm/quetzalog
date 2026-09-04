package spl

import (
	"reflect"
	"testing"

	"quetzalog/internal/spl/ast"
	"quetzalog/internal/spl/executor"
	"quetzalog/internal/spl/parser"
)

func TestParse_EvalBasic(t *testing.T) {
	q, err := parser.New(`eval score=100`)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	query, err := q.Parse()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(query.Commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(query.Commands))
	}
	eval, ok := query.Commands[0].(*ast.EvalNode)
	if !ok {
		t.Fatalf("expected EvalNode, got %T", query.Commands[0])
	}
	if eval.Field != "score" {
		t.Errorf("expected field 'score', got '%s'", eval.Field)
	}
	if eval.Expr != "100" {
		t.Errorf("expected expr '100', got '%s'", eval.Expr)
	}
}

func TestParse_EvalExpression(t *testing.T) {
	q, err := parser.New(`eval score=count*2`)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	query, err := q.Parse()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(query.Commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(query.Commands))
	}
	eval, ok := query.Commands[0].(*ast.EvalNode)
	if !ok {
		t.Fatalf("expected EvalNode, got %T", query.Commands[0])
	}
	if eval.Field != "score" {
		t.Errorf("expected field 'score', got '%s'", eval.Field)
	}
	if eval.Expr != "count * 2" {
		t.Errorf("expected expr 'count * 2', got '%s'", eval.Expr)
	}
}

func TestParse_EvalStringLiteral(t *testing.T) {
	q, err := parser.New(`eval status="failed"`)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	query, err := q.Parse()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(query.Commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(query.Commands))
	}
	eval, ok := query.Commands[0].(*ast.EvalNode)
	if !ok {
		t.Fatalf("expected EvalNode, got %T", query.Commands[0])
	}
	if eval.Field != "status" {
		t.Errorf("expected field 'status', got '%s'", eval.Field)
	}
	if eval.Expr != "failed" {
		t.Errorf("expected expr 'failed', got '%s'", eval.Expr)
	}
}

func TestParse_RexBasic(t *testing.T) {
	q, err := parser.New(`rex field=message "(?P<ip>\d+\.\d+\.\d+\.\d+)"`)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	query, err := q.Parse()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(query.Commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(query.Commands))
	}
	rex, ok := query.Commands[0].(*ast.RexNode)
	if !ok {
		t.Fatalf("expected RexNode, got %T", query.Commands[0])
	}
	if rex.Field != "message" {
		t.Errorf("expected field 'message', got '%s'", rex.Field)
	}
	if rex.Pattern != `(?P<ip>\d+\.\d+\.\d+\.\d+)` {
		t.Errorf("expected pattern, got '%s'", rex.Pattern)
	}
	if rex.Rename != "" {
		t.Errorf("expected empty rename, got '%s'", rex.Rename)
	}
}

func TestParse_RexWithRename(t *testing.T) {
	q, err := parser.New(`rex field=message "(?P<src_ip>\d+\.\d+\.\d+\.\d+)" rename=source_ip`)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	query, err := q.Parse()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(query.Commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(query.Commands))
	}
	rex, ok := query.Commands[0].(*ast.RexNode)
	if !ok {
		t.Fatalf("expected RexNode, got %T", query.Commands[0])
	}
	if rex.Rename != "source_ip" {
		t.Errorf("expected rename 'source_ip', got '%s'", rex.Rename)
	}
}

func TestParse_RexWithMode(t *testing.T) {
	q, err := parser.New(`rex field=message "(?P<ip>\d+\.\d+\.\d+\.\d+)" mode=multimatch`)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	query, err := q.Parse()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(query.Commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(query.Commands))
	}
	rex, ok := query.Commands[0].(*ast.RexNode)
	if !ok {
		t.Fatalf("expected RexNode, got %T", query.Commands[0])
	}
	if rex.Mode != "multimatch" {
		t.Errorf("expected mode 'multimatch', got '%s'", rex.Mode)
	}
}

func TestParse_PipeEval(t *testing.T) {
	q, err := parser.New(`source=auth | eval score=100 | sort -score`)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	query, err := q.Parse()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(query.Commands) != 3 {
		t.Fatalf("expected 3 commands, got %d", len(query.Commands))
	}

	search, ok := query.Commands[0].(*ast.SearchNode)
	if !ok || search.Fields["source"] != "auth" {
		t.Fatalf("unexpected search node: %+v", search)
	}

	eval, ok := query.Commands[1].(*ast.EvalNode)
	if !ok {
		t.Fatalf("expected EvalNode, got %T", query.Commands[1])
	}
	if eval.Field != "score" || eval.Expr != "100" {
		t.Errorf("unexpected eval node: %+v", eval)
	}

	sort, ok := query.Commands[2].(*ast.SortNode)
	if !ok || len(sort.Fields) != 1 || !sort.Fields[0].Desc {
		t.Fatalf("unexpected sort node: %+v", sort)
	}
}

func TestParse_EvalMultiExpr(t *testing.T) {
	q, err := parser.New(`eval score=100`)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	query, err := q.Parse()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(query.Commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(query.Commands))
	}
	eval, ok := query.Commands[0].(*ast.EvalNode)
	if !ok {
		t.Fatalf("expected EvalNode, got %T", query.Commands[0])
	}
	if eval.Field != "score" || eval.Expr != "100" {
		t.Errorf("expected score=100, got field='%s' expr='%s'", eval.Field, eval.Expr)
	}
}

func TestParse_PipeRex(t *testing.T) {
	q, err := parser.New(`source=auth | rex field=message "(?P<ip>\d+\.\d+\.\d+\.\d+)" | stats count by ip`)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	query, err := q.Parse()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(query.Commands) != 3 {
		t.Fatalf("expected 3 commands, got %d", len(query.Commands))
	}

	rex, ok := query.Commands[1].(*ast.RexNode)
	if !ok {
		t.Fatalf("expected RexNode at position 1, got %T", query.Commands[1])
	}
	if rex.Field != "message" {
		t.Errorf("expected field 'message', got '%s'", rex.Field)
	}
}

func TestParse_InvalidEval(t *testing.T) {
	p, err := parser.New(`eval`)
	if err != nil {
		t.Fatalf("expected no error on parser creation, got: %v", err)
	}
	_, err = p.Parse()
	if err == nil {
		t.Fatal("expected error for eval without expression")
	}
}

func TestParse_EvalWithAddition(t *testing.T) {
	q, err := parser.New(`eval risk=count+100`)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	query, err := q.Parse()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(query.Commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(query.Commands))
	}
	eval, ok := query.Commands[0].(*ast.EvalNode)
	if !ok {
		t.Fatalf("expected EvalNode, got %T", query.Commands[0])
	}
	if eval.Field != "risk" || eval.Expr != "count + 100" {
		t.Errorf("expected risk=count + 100, got field='%s' expr='%s'", eval.Field, eval.Expr)
	}
}

func TestEvalNodeString(t *testing.T) {
	node := &ast.EvalNode{Field: "score", Expr: "count * 2"}
	if node.NodeType() != "Eval" {
		t.Errorf("expected NodeType 'Eval', got '%s'", node.NodeType())
	}
}

func TestRexNodeString(t *testing.T) {
	node := &ast.RexNode{Field: "message", Pattern: `(?P<ip>\d+\.\d+\.\d+\.\d+)`}
	if node.NodeType() != "Rex" {
		t.Errorf("expected NodeType 'Rex', got '%s'", node.NodeType())
	}
}

func BenchmarkParseEval(b *testing.B) {
	input := `eval score=count*2 | eval risk="high"`
	for i := 0; i < b.N; i++ {
		p, err := parser.New(input)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
		_, err = p.Parse()
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

func BenchmarkParseRex(b *testing.B) {
	input := `rex field=message "(?P<ip>\d+\.\d+\.\d+\.\d+)"`
	for i := 0; i < b.N; i++ {
		p, err := parser.New(input)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
		_, err = p.Parse()
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

func TestEvalExpr_Numeric(t *testing.T) {
	ev, err := executor.NewEvalEvaluator()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	result := ev.EvalExpr(map[string]any{}, "42")
	numVal, ok := result.(float64)
	if !ok {
		t.Fatalf("expected float64, got %T", result)
	}
	if numVal != 42 {
		t.Errorf("expected 42, got %f", numVal)
	}
}

func TestEvalExpr_FieldRef(t *testing.T) {
	ev, err := executor.NewEvalEvaluator()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	result := ev.EvalExpr(map[string]any{"count": float64(10)}, "count")
	numVal, ok := result.(float64)
	if !ok {
		t.Fatalf("expected float64, got %T", result)
	}
	if numVal != 10 {
		t.Errorf("expected 10, got %f", numVal)
	}
}

func TestEvalExpr_Multiplication(t *testing.T) {
	ev, err := executor.NewEvalEvaluator()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	result := ev.EvalExpr(map[string]any{"count": float64(5)}, "count*2")
	numVal, ok := result.(float64)
	if !ok {
		t.Fatalf("expected float64, got %T", result)
	}
	if numVal != 10 {
		t.Errorf("expected 10, got %f", numVal)
	}
}

func TestEvalExpr_Addition(t *testing.T) {
	ev, err := executor.NewEvalEvaluator()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	result := ev.EvalExpr(map[string]any{"count": float64(5)}, "count+100")
	numVal, ok := result.(float64)
	if !ok {
		t.Fatalf("expected float64, got %T", result)
	}
	if numVal != 105 {
		t.Errorf("expected 105, got %f", numVal)
	}
}

func TestEvalExpr_StringLiteral(t *testing.T) {
	ev, err := executor.NewEvalEvaluator()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	result := ev.EvalExpr(map[string]any{}, `"failed"`)
	if result != "failed" {
		t.Errorf("expected 'failed', got '%s'", result)
	}
}

func TestEvalExpr_UnresolvedField(t *testing.T) {
	ev, err := executor.NewEvalEvaluator()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	result := ev.EvalExpr(map[string]any{}, "unknown_field")
	if result != "unknown_field" {
		t.Errorf("expected 'unknown_field' as literal, got '%s'", result)
	}
}

func TestTransformEval_Basic(t *testing.T) {
	ev, err := executor.NewEvalEvaluator()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	events := []map[string]any{
		{"count": float64(10)},
		{"count": float64(20)},
		{"count": float64(30)},
	}
	nodes := []ast.Node{
		&ast.EvalNode{Field: "score", Expr: "count*2"},
	}

	ev.TransformEval(events, nodes)

	for i, expected := range []float64{20, 40, 60} {
		if events[i]["score"] != expected {
			t.Errorf("event[%d] score: expected %f, got %v", i, expected, events[i]["score"])
		}
	}
}

func TestTransformEval_StringField(t *testing.T) {
	ev, err := executor.NewEvalEvaluator()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	events := []map[string]any{
		{"event_type": "login"},
		{"event_type": "login"},
	}
	nodes := []ast.Node{
		&ast.EvalNode{Field: "is_login", Expr: `"yes"`},
	}

	ev.TransformEval(events, nodes)

	for i, event := range events {
		if event["is_login"] != "yes" {
			t.Errorf("event[%d] is_login: expected 'yes', got '%s'", i, event["is_login"])
		}
	}
}

func TestTransformEval_FieldRef(t *testing.T) {
	ev, err := executor.NewEvalEvaluator()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	events := []map[string]any{
		{"severity_rank": float64(4)},
		{"severity_rank": float64(5)},
	}
	nodes := []ast.Node{
		&ast.EvalNode{Field: "sev", Expr: "severity_rank"},
	}

	ev.TransformEval(events, nodes)

	if events[0]["sev"] != float64(4) {
		t.Errorf("expected sev=4, got %v", events[0]["sev"])
	}
	if events[1]["sev"] != float64(5) {
		t.Errorf("expected sev=5, got %v", events[1]["sev"])
	}
}

func TestEvalEvaluator_EvaluateExpr(t *testing.T) {
	ev, err := executor.NewEvalEvaluator()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	tests := []struct {
		name   string
		event  map[string]any
		expr   string
		expect any
	}{
		{"number literal", map[string]any{}, "42", 42.0},
		{"field reference", map[string]any{"val": float64(10)}, "val", 10.0},
		{"multiply", map[string]any{"val": float64(5)}, "val*3", 15.0},
		{"add", map[string]any{"val": float64(5)}, "val+10", 15.0},
		{"string literal", map[string]any{}, `"hello"`, "hello"},
		{"unresolved field", map[string]any{}, "missing", "missing"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ev.EvalExpr(tt.event, tt.expr)
			if !reflect.DeepEqual(result, tt.expect) {
				t.Errorf("expected %v, got %v", tt.expect, result)
			}
		})
	}
}
