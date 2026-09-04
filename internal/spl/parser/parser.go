package parser

import (
	"fmt"
	"strconv"
	"strings"

	"quetzalog/internal/spl/ast"
	"quetzalog/internal/spl/lexer"
)

type Parser struct {
	lexer  *lexer.Lexer
	tokens []lexer.Token
	pos    int
}

func New(input string) (*Parser, error) {
	l := lexer.NewLexer(input)
	var tokens []lexer.Token
	for {
		tok := l.NextToken()
		tokens = append(tokens, tok)
		if tok.Type == lexer.EOF {
			break
		}
	}
	p := &Parser{
		lexer:  l,
		tokens: tokens,
		pos:    0,
	}
	return p, nil
}

func (p *Parser) Parse() (*ast.Query, error) {
	commands, err := p.parseCommands()
	if err != nil {
		return nil, err
	}
	return &ast.Query{Commands: commands}, nil
}

func (p *Parser) parseCommands() ([]ast.Node, error) {
	var commands []ast.Node

	for p.current().Type != lexer.EOF {
		if p.current().Type == lexer.PIPE {
			p.advance()
		}

		cmd, err := p.parseCommand()
		if err != nil {
			return nil, err
		}
		commands = append(commands, cmd)
	}

	return commands, nil
}

func (p *Parser) parseCommand() (ast.Node, error) {
	tok := p.current()
	name := strings.ToLower(tok.Value)

	switch name {
	case "search", "":
		return p.parseSearch()
	case "where":
		p.advance()
		return p.parseWhere()
	case "stats":
		p.advance()
		return p.parseStats()
	case "sort":
		p.advance()
		return p.parseSort()
	case "head":
		p.advance()
		return p.parseHead()
	case "tail":
		p.advance()
		return p.parseTail()
	case "dedup":
		p.advance()
		return p.parseDedup()
	case "rename":
		p.advance()
		return p.parseRename()
	case "table":
		p.advance()
		return p.parseTable()
	case "eval":
		p.advance()
		return p.parseEval()
	case "timechart":
		p.advance()
		return p.parseTimechart()
	case "rex":
		p.advance()
		return p.parseRex()
	default:
		return p.parseSearch()
	}
}

func (p *Parser) parseArgs() ([]string, error) {
	var args []string

	for p.current().Type != lexer.EOF && p.current().Type != lexer.PIPE {
		tok := p.current()

		if tok.Type == lexer.PIPE {
			break
		}

		if tok.Type == lexer.COMMA {
			p.advance()
			continue
		}

		// Check for key=value pattern
		if tok.Type == lexer.IDENT && p.peek().Type == lexer.OP && p.peek().Value == "=" {
			p.advance() // IDENT
			p.advance() // OP "="

			if p.current().Type == lexer.IDENT || p.current().Type == lexer.STRING || p.current().Type == lexer.NUMBER {
				args = append(args, tok.Value+"="+p.current().Value)
			} else {
				return nil, fmt.Errorf("expected value after '=' at position %d", p.pos)
			}
			p.advance()
			continue
		}

		// Handle -count pattern for sort
		if tok.Type == lexer.MINUS && p.peek().Type == lexer.IDENT {
			p.advance() // MINUS
			args = append(args, "-"+p.current().Value)
			p.advance()
			continue
		}

		args = append(args, tok.Value)
		p.advance()
	}

	return args, nil
}

func (p *Parser) peek() lexer.Token {
	next := p.pos + 1
	if next >= len(p.tokens) {
		return lexer.Token{Type: lexer.EOF}
	}
	return p.tokens[next]
}

func (p *Parser) parseSearch() (ast.Node, error) {
	node := &ast.SearchNode{
		Fields: make(map[string]string),
	}

	args, err := p.parseArgs()
	if err != nil {
		return nil, err
	}

	for _, arg := range args {
		if idx := strings.Index(arg, "="); idx > 0 {
			key := strings.TrimSpace(arg[:idx])
			value := strings.Trim(arg[idx+1:], "\"'")
			node.Fields[key] = value
		} else {
			if node.Text != "" {
				node.Text += " " + arg
			} else {
				node.Text = arg
			}
		}
	}

	return node, nil
}

func (p *Parser) parseWhere() (ast.Node, error) {
	node := &ast.WhereNode{}

	conditions, err := p.parseConditions()
	if err != nil {
		return nil, err
	}
	node.Conditions = conditions

	return node, nil
}

func (p *Parser) parseConditions() ([]ast.Condition, error) {
	var conditions []ast.Condition

	for {
		if p.current().Type == lexer.EOF || p.current().Type == lexer.PIPE {
			break
		}

		tok := p.current()
		if tok.Type != lexer.IDENT {
			return nil, fmt.Errorf("expected field name at position %d", p.pos)
		}
		field := tok.Value
		p.advance()

		if p.current().Type != lexer.OP {
			return nil, fmt.Errorf("expected operator at position %d", p.pos)
		}
		operator := p.current().Value
		p.advance()

		var value string
		if p.current().Type == lexer.IDENT || p.current().Type == lexer.STRING || p.current().Type == lexer.NUMBER {
			value = p.current().Value
			p.advance()
		} else {
			return nil, fmt.Errorf("expected value at position %d", p.pos)
		}

		conditions = append(conditions, ast.Condition{
			Field:    field,
			Operator: operator,
			Value:    value,
		})

		// Handle "and" / "or" continuations
		if p.current().Type == lexer.IDENT {
			lower := strings.ToLower(p.current().Value)
			if lower == "and" || lower == "or" {
				p.advance()
				continue
			}
		}
		break
	}

	return conditions, nil
}

func (p *Parser) parseStats() (ast.Node, error) {
	node := &ast.StatsNode{}

	args, err := p.parseArgs()
	if err != nil {
		return nil, err
	}

	var groupBy []string
	for _, arg := range args {
		lower := strings.ToLower(arg)
		if lower == "by" {
			continue
		}

		if strings.HasPrefix(lower, "count(") || strings.HasPrefix(lower, "values(") ||
			strings.HasPrefix(lower, "dc(") || strings.HasPrefix(lower, "sum(") ||
			strings.HasPrefix(lower, "avg(") || strings.HasPrefix(lower, "min(") ||
			strings.HasPrefix(lower, "max(") {
			agg, err := p.parseAggregation(arg)
			if err != nil {
				return nil, err
			}
			node.Aggs = append(node.Aggs, agg)
		} else if lower == "count" {
			node.Aggs = append(node.Aggs, ast.Aggregation{Function: "count", Field: "*"})
		} else {
			groupBy = append(groupBy, arg)
		}
	}
	node.GroupBy = groupBy

	return node, nil
}

func (p *Parser) parseAggregation(arg string) (ast.Aggregation, error) {
	agg := ast.Aggregation{}

	if idx := strings.Index(arg, " as "); idx > 0 {
		agg.Function, agg.Field, agg.Alias = parseAggFunc(arg[:idx])
	} else if idx := strings.Index(arg, " AS "); idx > 0 {
		agg.Function, agg.Field, agg.Alias = parseAggFunc(arg[:idx])
	} else {
		agg.Function, agg.Field, agg.Alias = parseAggFunc(arg)
	}

	return agg, nil
}

func parseAggFunc(s string) (function, field, alias string) {
	s = strings.TrimSpace(s)
	if idx := strings.IndexByte(s, '('); idx > 0 {
		funcName := strings.ToLower(s[:idx])
		content := strings.TrimRight(strings.TrimSpace(s[idx+1:]), ")")
		if content == "*" {
			return funcName, "*", ""
		}
		return funcName, content, ""
	}
	return "", "", s
}

func (p *Parser) parseSort() (ast.Node, error) {
	node := &ast.SortNode{}

	args, err := p.parseArgs()
	if err != nil {
		return nil, err
	}

	for _, arg := range args {
		if arg == "by" {
			continue
		}
		desc := false
		field := arg
		if strings.HasPrefix(arg, "-") {
			desc = true
			field = arg[1:]
		}
		node.Fields = append(node.Fields, ast.SortField{
			Field: field,
			Desc:  desc,
		})
	}

	return node, nil
}

func (p *Parser) parseHead() (ast.Node, error) {
	args, err := p.parseArgs()
	if err != nil {
		return nil, err
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("head requires a number argument")
	}
	n, err := strconv.Atoi(args[0])
	if err != nil {
		return nil, fmt.Errorf("head argument must be a number: %s", args[0])
	}
	return &ast.HeadNode{N: n}, nil
}

func (p *Parser) parseTail() (ast.Node, error) {
	args, err := p.parseArgs()
	if err != nil {
		return nil, err
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("tail requires a number argument")
	}
	n, err := strconv.Atoi(args[0])
	if err != nil {
		return nil, fmt.Errorf("tail argument must be a number: %s", args[0])
	}
	return &ast.TailNode{N: n}, nil
}

func (p *Parser) parseDedup() (ast.Node, error) {
	args, err := p.parseArgs()
	if err != nil {
		return nil, err
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("dedup requires a field name")
	}
	return &ast.DedupNode{Field: args[0]}, nil
}

func (p *Parser) parseRename() (ast.Node, error) {
	node := &ast.RenameNode{Mappings: make(map[string]string)}

	args, err := p.parseArgs()
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(args); i++ {
		field := args[i]
		if i+1 < len(args) && strings.EqualFold(args[i+1], "as") {
			if i+2 < len(args) {
				node.Mappings[field] = args[i+2]
				i += 2
			} else {
				return nil, fmt.Errorf("rename: expected field name after 'as' at position %d", i)
			}
		} else {
			node.Mappings[field] = field
			i--
		}
	}

	return node, nil
}

func (p *Parser) parseTable() (ast.Node, error) {
	args, err := p.parseArgs()
	if err != nil {
		return nil, err
	}

	node := &ast.TableNode{Fields: args}
	return node, nil
}

func (p *Parser) parseEval() (ast.Node, error) {
	node := &ast.EvalNode{}

	// Collect tokens after "eval" until EOF or PIPE
	var rawArgs []string
	for p.current().Type != lexer.EOF && p.current().Type != lexer.PIPE {
		rawArgs = append(rawArgs, p.current().Value)
		p.advance()
	}

	if len(rawArgs) == 0 {
		return nil, fmt.Errorf("eval requires an expression")
	}

	// Find the first = to split field and expression
	found := false
	for i, tok := range rawArgs {
		if tok == "=" {
			// Field is everything before the =
			var fieldParts []string
			for j := 0; j < i; j++ {
				fieldParts = append(fieldParts, rawArgs[j])
			}
			node.Field = strings.Join(fieldParts, " ")
			node.Field = strings.TrimSpace(node.Field)

			// Expression is everything after the =
			var exprParts []string
			for j := i + 1; j < len(rawArgs); j++ {
				exprParts = append(exprParts, rawArgs[j])
			}
			node.Expr = strings.Join(exprParts, " ")
			node.Expr = strings.TrimSpace(node.Expr)
			// Strip surrounding quotes
			node.Expr = strings.Trim(node.Expr, "\"'")
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("eval: expected field=value at position %d", p.pos)
	}

	return node, nil
}

func (p *Parser) parseTimechart() (ast.Node, error) {
	node := &ast.TimechartNode{}

	args, err := p.parseArgs()
	if err != nil {
		return nil, err
	}

	var groupBy []string
	var span string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "span=") {
			span = strings.TrimPrefix(arg, "span=")
			continue
		}

		lower := strings.ToLower(arg)
		if lower == "by" {
			i++
			for i < len(args) {
				groupBy = append(groupBy, args[i])
				i++
			}
			break
		}

		if strings.HasPrefix(lower, "count(") || strings.HasPrefix(lower, "values(") ||
			strings.HasPrefix(lower, "dc(") || strings.HasPrefix(lower, "sum(") ||
			strings.HasPrefix(lower, "avg(") || strings.HasPrefix(lower, "min(") ||
			strings.HasPrefix(lower, "max(") {
			agg, err := p.parseAggregation(arg)
			if err != nil {
				return nil, err
			}
			node.Func = agg
		}
	}

	node.Span = span
	node.GroupBy = groupBy

	return node, nil
}

func (p *Parser) parseRex() (ast.Node, error) {
	node := &ast.RexNode{}

	args, err := p.parseArgs()
	if err != nil {
		return nil, err
	}

	var pattern string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "field=") {
			node.Field = strings.TrimPrefix(arg, "field=")
			continue
		}

		if strings.HasPrefix(arg, "rename=") {
			node.Rename = strings.TrimPrefix(arg, "rename=")
			continue
		}

		if strings.HasPrefix(arg, "mode=") {
			node.Mode = strings.TrimPrefix(arg, "mode=")
			continue
		}

		pattern = arg
	}

	node.Pattern = pattern

	return node, nil
}

func (p *Parser) current() lexer.Token {
	if p.pos >= len(p.tokens) {
		return lexer.Token{Type: lexer.EOF}
	}
	return p.tokens[p.pos]
}

func (p *Parser) advance() lexer.Token {
	tok := p.current()
	p.pos++
	return tok
}
