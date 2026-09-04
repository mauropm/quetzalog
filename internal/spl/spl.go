package spl

import (
	"context"
	"database/sql"

	"quetzalog/internal/spl/ast"
	"quetzalog/internal/spl/executor"
	"quetzalog/internal/spl/parser"
)

func Parse(input string) (*ast.Query, error) {
	p, err := parser.New(input)
	if err != nil {
		return nil, err
	}
	return p.Parse()
}

func Execute(db *sql.DB, ctx context.Context, input string) ([]map[string]any, []string, error) {
	e := executor.New(db)
	return e.ExecuteString(ctx, input)
}
