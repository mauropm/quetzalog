package spl

import (
	"quetzalog/internal/spl/ast"
	"testing"
)

func TestParse_BareSearch(t *testing.T) {
	q, err := Parse(`source=auth`)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(q.Commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(q.Commands))
	}
	search, ok := q.Commands[0].(*ast.SearchNode)
	if !ok {
		t.Fatalf("expected SearchNode, got %T", q.Commands[0])
	}
	if search.Fields["source"] != "auth" {
		t.Errorf("expected source field='auth', got '%s'", search.Fields["source"])
	}
}

func TestParse_Where(t *testing.T) {
	q, err := Parse(`where status="failed"`)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(q.Commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(q.Commands))
	}
	where, ok := q.Commands[0].(*ast.WhereNode)
	if !ok {
		t.Fatalf("expected WhereNode, got %T", q.Commands[0])
	}
	if len(where.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(where.Conditions))
	}
	if where.Conditions[0].Field != "status" {
		t.Errorf("expected field 'status', got '%s'", where.Conditions[0].Field)
	}
	if where.Conditions[0].Operator != "=" {
		t.Errorf("expected op '=', got '%s'", where.Conditions[0].Operator)
	}
	if where.Conditions[0].Value != "failed" {
		t.Errorf("expected value 'failed', got '%s'", where.Conditions[0].Value)
	}
}

func TestParse_Stats(t *testing.T) {
	q, err := Parse(`stats count by user`)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(q.Commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(q.Commands))
	}
	stats, ok := q.Commands[0].(*ast.StatsNode)
	if !ok {
		t.Fatalf("expected StatsNode, got %T", q.Commands[0])
	}
	if len(stats.Aggs) != 1 {
		t.Fatalf("expected 1 aggregation, got %d", len(stats.Aggs))
	}
	if stats.Aggs[0].Function != "count" {
		t.Errorf("expected function 'count', got '%s'", stats.Aggs[0].Function)
	}
	if len(stats.GroupBy) != 1 || stats.GroupBy[0] != "user" {
		t.Errorf("expected group by [user], got %v", stats.GroupBy)
	}
}

func TestParse_Sort(t *testing.T) {
	q, err := Parse(`sort -count`)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(q.Commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(q.Commands))
	}
	sort, ok := q.Commands[0].(*ast.SortNode)
	if !ok {
		t.Fatalf("expected SortNode, got %T", q.Commands[0])
	}
	if len(sort.Fields) != 1 {
		t.Fatalf("expected 1 sort field, got %d", len(sort.Fields))
	}
	if sort.Fields[0].Field != "count" {
		t.Errorf("expected field 'count', got '%s'", sort.Fields[0].Field)
	}
	if !sort.Fields[0].Desc {
		t.Errorf("expected desc sort, got asc")
	}
}

func TestParse_Head(t *testing.T) {
	q, err := Parse(`head 10`)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(q.Commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(q.Commands))
	}
	head, ok := q.Commands[0].(*ast.HeadNode)
	if !ok {
		t.Fatalf("expected HeadNode, got %T", q.Commands[0])
	}
	if head.N != 10 {
		t.Errorf("expected N 10, got %d", head.N)
	}
}

func TestParse_PipeChain(t *testing.T) {
	q, err := Parse(`source=auth | where status="failed" | stats count by user`)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(q.Commands) != 3 {
		t.Fatalf("expected 3 commands, got %d", len(q.Commands))
	}

	search, ok := q.Commands[0].(*ast.SearchNode)
	if !ok {
		t.Fatalf("expected SearchNode, got %T", q.Commands[0])
	}
	if search.Fields["source"] != "auth" {
		t.Errorf("expected source field='auth', got '%s'", search.Fields["source"])
	}

	where, ok := q.Commands[1].(*ast.WhereNode)
	if !ok {
		t.Fatalf("expected WhereNode, got %T", q.Commands[1])
	}
	if len(where.Conditions) != 1 || where.Conditions[0].Field != "status" || where.Conditions[0].Value != "failed" {
		t.Errorf("unexpected where node: %+v", where)
	}

	stats, ok := q.Commands[2].(*ast.StatsNode)
	if !ok {
		t.Fatalf("expected StatsNode, got %T", q.Commands[2])
	}
	if stats.Aggs[0].Function != "count" || len(stats.GroupBy) != 1 || stats.GroupBy[0] != "user" {
		t.Errorf("unexpected stats node: %+v", stats)
	}
}

func TestParse_Dedup(t *testing.T) {
	q, err := Parse(`dedup user`)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(q.Commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(q.Commands))
	}
	dedup, ok := q.Commands[0].(*ast.DedupNode)
	if !ok {
		t.Fatalf("expected DedupNode, got %T", q.Commands[0])
	}
	if dedup.Field != "user" {
		t.Errorf("expected field 'user', got '%s'", dedup.Field)
	}
}

func TestParse_Tail(t *testing.T) {
	q, err := Parse(`tail 5`)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(q.Commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(q.Commands))
	}
	tail, ok := q.Commands[0].(*ast.TailNode)
	if !ok {
		t.Fatalf("expected TailNode, got %T", q.Commands[0])
	}
	if tail.N != 5 {
		t.Errorf("expected N 5, got %d", tail.N)
	}
}
