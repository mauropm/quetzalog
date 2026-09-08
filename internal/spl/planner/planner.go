package planner

import (
	"fmt"
	"regexp"
	"strings"

	"quetzalog/internal/spl/ast"
)

// identRe whitelists identifiers that may be embedded into generated SQL.
// Anything else fails planning (defense in depth against SQL injection via
// field names).
var identRe = regexp.MustCompile(`^[A-Za-z0-9_.]+$`)

func checkIdent(p *Plan, id string) {
	if id == "" || id == "*" {
		return
	}
	if p.Err == nil && !identRe.MatchString(id) {
		p.Err = fmt.Errorf("invalid identifier %q in query", id)
	}
}

type Plan struct {
	SelectClause  string
	WhereClause   string
	GroupByClause string
	OrderByClause string
	LimitClause   string
	Args          []any
	IsAggregation bool
	Columns       []string
	Err           error
}

func PlanQuery(q *ast.Query) *Plan {
	plan := &Plan{
		SelectClause: "SELECT *",
		Args:         []any{},
	}

	plan.buildSelect(q.Commands)
	plan.buildWhere(q.Commands)
	plan.buildGroupBy(q.Commands)
	plan.buildOrderBy(q.Commands)
	plan.buildLimit(q.Commands)

	return plan
}

func (p *Plan) buildSelect(commands []ast.Node) {
	var selectFields []string
	var groupByFields []string
	var hasAgg bool

	for _, cmd := range commands {
		switch n := cmd.(type) {
		case *ast.SearchNode:
			for _, v := range n.Fields {
				if v == "*" {
					continue
				}
			}
		case *ast.StatsNode:
			hasAgg = true
			for _, agg := range n.Aggs {
				if agg.Function == "count" || agg.Function == "values" ||
					agg.Function == "dc" || agg.Function == "sum" ||
					agg.Function == "avg" || agg.Function == "min" ||
					agg.Function == "max" {
					checkIdent(p, agg.Field)
					checkIdent(p, agg.Alias)
					var columnName string
					if agg.Alias != "" {
						columnName = agg.Alias
					} else if agg.Field == "*" {
						columnName = fmt.Sprintf("%s_%s", agg.Function, "count")
					} else {
						columnName = fmt.Sprintf("%s_%s", agg.Function, agg.Field)
					}
					selectFields = append(selectFields, fmt.Sprintf("%s(%s) AS %s", agg.Function, agg.Field, columnName))
					p.Columns = append(p.Columns, columnName)
				}
			}
			for _, field := range n.GroupBy {
				checkIdent(p, field)
				groupByFields = append(groupByFields, field)
				p.Columns = append(p.Columns, field)
			}
		case *ast.TableNode:
			for _, f := range n.Fields {
				checkIdent(p, f)
			}
			selectFields = n.Fields
			p.Columns = n.Fields
		case *ast.RenameNode:
			// Rename affects column mapping, not SQL directly
		}
	}

	if hasAgg || len(groupByFields) > 0 {
		p.IsAggregation = true
		if len(selectFields) > 0 {
			p.SelectClause = fmt.Sprintf("SELECT %s", strings.Join(selectFields, ", "))
		} else {
			p.SelectClause = "SELECT " + strings.Join(groupByFields, ", ")
		}
		p.GroupByClause = "GROUP BY " + strings.Join(groupByFields, ", ")
		return
	}

	if len(selectFields) > 0 {
		p.SelectClause = fmt.Sprintf("SELECT %s", strings.Join(selectFields, ", "))
		p.Columns = selectFields
	}
}

func (p *Plan) buildWhere(commands []ast.Node) {
	var clauses []string

	for _, cmd := range commands {
		switch n := cmd.(type) {
		case *ast.SearchNode:
			for field, value := range n.Fields {
				checkIdent(p, field)
				clauses = append(clauses, fmt.Sprintf("%s = ?", field))
				p.Args = append(p.Args, value)
			}
		case *ast.WhereNode:
			for _, cond := range n.Conditions {
				checkIdent(p, cond.Field)
				clause, arg := buildConditionSQL(cond)
				clauses = append(clauses, clause)
				if arg != nil {
					p.Args = append(p.Args, arg)
				}
			}
		}
	}

	if len(clauses) > 0 {
		p.WhereClause = "WHERE " + strings.Join(clauses, " AND ")
	}
}

func buildConditionSQL(cond ast.Condition) (clause string, arg any) {
	switch cond.Operator {
	case "=":
		return fmt.Sprintf("%s = ?", cond.Field), cond.Value
	case "!=":
		return fmt.Sprintf("%s != ?", cond.Field), cond.Value
	case ">":
		return fmt.Sprintf("%s > ?", cond.Field), cond.Value
	case "<":
		return fmt.Sprintf("%s < ?", cond.Field), cond.Value
	case ">=":
		return fmt.Sprintf("%s >= ?", cond.Field), cond.Value
	case "<=":
		return fmt.Sprintf("%s <= ?", cond.Field), cond.Value
	case "*=":
		return fmt.Sprintf("%s LIKE ?", cond.Field), fmt.Sprintf("%%%s%%", cond.Value)
	case "in":
		vals := strings.Split(cond.Value, ",")
		placeholders := make([]string, len(vals))
		for i := range placeholders {
			placeholders[i] = "?"
		}
		return fmt.Sprintf("%s IN (%s)", cond.Field, strings.Join(placeholders, ", ")), strings.Join(vals, ",")
	case "not in":
		vals := strings.Split(cond.Value, ",")
		placeholders := make([]string, len(vals))
		for i := range placeholders {
			placeholders[i] = "?"
		}
		return fmt.Sprintf("%s NOT IN (%s)", cond.Field, strings.Join(placeholders, ", ")), strings.Join(vals, ",")
	default:
		// Treat as regex
		return fmt.Sprintf("%s REGEXP ?", cond.Field), cond.Value
	}
}

func (p *Plan) buildGroupBy(commands []ast.Node) {
	for _, cmd := range commands {
		if n, ok := cmd.(*ast.StatsNode); ok && len(n.GroupBy) > 0 && p.GroupByClause == "" {
			for _, field := range n.GroupBy {
				checkIdent(p, field)
				p.Columns = append(p.Columns, field)
			}
			p.GroupByClause = "GROUP BY " + strings.Join(n.GroupBy, ", ")
		}
	}
}

func (p *Plan) buildOrderBy(commands []ast.Node) {
	var fields []string

	for _, cmd := range commands {
		if n, ok := cmd.(*ast.SortNode); ok {
			for _, f := range n.Fields {
				checkIdent(p, f.Field)
				dir := "ASC"
				if f.Desc {
					dir = "DESC"
				}
				fields = append(fields, fmt.Sprintf("%s %s", f.Field, dir))
			}
		}
	}

	if len(fields) > 0 {
		p.OrderByClause = "ORDER BY " + strings.Join(fields, ", ")
	}
}

func (p *Plan) buildLimit(commands []ast.Node) {
	for _, cmd := range commands {
		switch n := cmd.(type) {
		case *ast.HeadNode:
			p.LimitClause = fmt.Sprintf("LIMIT %d", n.N)
		case *ast.TailNode:
			p.LimitClause = fmt.Sprintf("LIMIT %d", n.N)
		}
	}
}

func BuildSQL(plan *Plan) (string, error) {
	if plan.Err != nil {
		return "", plan.Err
	}
	queryParts := []string{
		plan.SelectClause,
		"FROM events",
	}

	if plan.WhereClause != "" {
		queryParts = append(queryParts, plan.WhereClause)
	}
	if plan.GroupByClause != "" {
		queryParts = append(queryParts, plan.GroupByClause)
	}
	if plan.OrderByClause != "" {
		queryParts = append(queryParts, plan.OrderByClause)
	}
	if plan.LimitClause != "" {
		queryParts = append(queryParts, plan.LimitClause)
	}

	return strings.Join(queryParts, " "), nil
}

func ColumnMappings(commands []ast.Node) map[string]string {
	mappings := make(map[string]string)

	for _, cmd := range commands {
		if n, ok := cmd.(*ast.RenameNode); ok {
			for old, new := range n.Mappings {
				mappings[old] = new
			}
		}
	}

	return mappings
}

func ExtractFields(commands []ast.Node) []string {
	var fields []string
	seen := make(map[string]bool)

	for _, cmd := range commands {
		switch n := cmd.(type) {
		case *ast.SearchNode:
			for k := range n.Fields {
				if !seen[k] {
					fields = append(fields, k)
					seen[k] = true
				}
			}
		case *ast.WhereNode:
			for _, cond := range n.Conditions {
				if !seen[cond.Field] {
					fields = append(fields, cond.Field)
					seen[cond.Field] = true
				}
			}
		case *ast.StatsNode:
			for _, agg := range n.Aggs {
				if agg.Field != "*" && !seen[agg.Field] {
					fields = append(fields, agg.Field)
					seen[agg.Field] = true
				}
			}
			for _, f := range n.GroupBy {
				if !seen[f] {
					fields = append(fields, f)
					seen[f] = true
				}
			}
		case *ast.SortNode:
			for _, f := range n.Fields {
				if !seen[f.Field] {
					fields = append(fields, f.Field)
					seen[f.Field] = true
				}
			}
		case *ast.TableNode:
			for _, f := range n.Fields {
				if !seen[f] {
					fields = append(fields, f)
					seen[f] = true
				}
			}
		}
	}

	return fields
}

func EstimateResultSize(commands []ast.Node) int {
	limit := 0

	for _, cmd := range commands {
		switch n := cmd.(type) {
		case *ast.HeadNode:
			limit = n.N
		case *ast.TailNode:
			if n.N < limit || limit == 0 {
				limit = n.N
			}
		}
	}

	if limit == 0 {
		return 100
	}
	return limit
}

func HasFilter(commands []ast.Node) bool {
	for _, cmd := range commands {
		switch cmd.(type) {
		case *ast.SearchNode, *ast.WhereNode:
			return true
		}
	}
	return false
}
