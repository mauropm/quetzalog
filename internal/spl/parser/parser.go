// Package parser turns an SPL token stream into the ast.Query tree. It is a
// hand-written recursive-descent parser (NOT a "|"-split) that supports
// boolean expressions with precedence (AND/OR/NOT, parentheses), field=value
// pairs, quoted strings, negative/decimal numbers, IN/NOT IN, LIKE, IS [NOT]
// NULL, function-call aggregations, and every builder-supported command.
package parser

import (
	"fmt"
	"strconv"
	"strings"

	"quetzalog/internal/spl/ast"
	"quetzalog/internal/spl/lexer"
)

// Parser holds a token slice with a cursor.
type Parser struct {
	tokens []lexer.Token
	input  string
	pos    int
}

// New tokenizes input and prepares a parser.
func New(input string) (*Parser, error) {
	tokens, err := lexer.Tokenize(input)
	if err != nil {
		return nil, err
	}
	return &Parser{tokens: tokens, input: input}, nil
}

// Parse returns the query tree.
func (p *Parser) Parse() (*ast.Query, error) {
	groups := p.splitPipes()
	if len(groups) == 0 {
		return &ast.Query{Version: 1}, nil
	}
	cmds := make([]ast.Node, 0, len(groups))
	for i, g := range groups {
		if len(g) == 0 {
			continue
		}
		node, err := p.dispatch(g, i == 0)
		if err != nil {
			return nil, err
		}
		cmds = append(cmds, node)
	}
	return &ast.Query{Version: 1, Commands: cmds}, nil
}

// splitPipes splits the (non-EOF) tokens into per-command groups at Pipe tokens.
func (p *Parser) splitPipes() [][]lexer.Token {
	var groups [][]lexer.Token
	var cur []lexer.Token
	for _, t := range p.tokens {
		if t.Kind == lexer.TokenEOF {
			continue
		}
		if t.Kind == lexer.TokenPipe {
			if len(cur) > 0 {
				groups = append(groups, cur)
				cur = nil
			}
			continue
		}
		cur = append(cur, t)
	}
	if len(cur) > 0 {
		groups = append(groups, cur)
	}
	return groups
}

// commandKeywords are treated as explicit commands when they lead a group.
var commandKeywords = map[string]func(*Parser, []lexer.Token) (ast.Node, error){
	"search":      parseSearch,
	"where":       parseWhere,
	"eval":        parseEval,
	"fields":      parseFields,
	"table":       parseTable,
	"rename":      parseRename,
	"stats":       parseStats,
	"timechart":   parseTimechart,
	"sort":        parseSort,
	"head":        parseHead,
	"tail":        parseTail,
	"dedup":       parseDedup,
	"rex":         parseRex,
	"bin":         parseBin,
	"lookup":      parseLookup,
	"eventstats":  parseEventstats,
	"streamstats": parseStreamstats,
}

func (p *Parser) dispatch(g []lexer.Token, isSearch bool) (ast.Node, error) {
	if g[0].Kind == lexer.TokenName {
		if fn, ok := commandKeywords[strings.ToLower(g[0].Value)]; ok {
			return fn(p, g[1:])
		}
	}
	// A pipe segment that leads with a non-keyword token is not a command we
	// understand; preserve it verbatim so a real SPL query is never destroyed by
	// an unsupported stage. The FIRST segment, by contrast, is the base search
	// expression and may legitimately lead with a bare term.
	if !isSearch {
		return &ast.UnsupportedNode{Name: commandNameOf(g), Raw: p.rawSlice(g)}, nil
	}
	return parseSearch(p, g)
}

// commandNameOf returns the lowercased leading command name for an unsupported
// group, used purely for messaging.
func commandNameOf(g []lexer.Token) string {
	if len(g) == 0 {
		return ""
	}
	return strings.ToLower(g[0].Value)
}

// rawSlice reconstructs the original source text spanned by a token group.
func (p *Parser) rawSlice(g []lexer.Token) string {
	if len(g) == 0 || p.input == "" {
		return ""
	}
	start := g[0].Pos
	last := g[len(g)-1]
	end := last.Pos + len(last.Raw)
	if start < 0 || start >= len(p.input) {
		return ""
	}
	if end > len(p.input) {
		end = len(p.input)
	}
	return strings.TrimSpace(p.input[start:end])
}

// ─────────────────────────── expression parser ───────────────────────────
// Grammar (filter expressions used by search/where):
//   or    := and (OR and)*
//   and   := unary (AND? unary)*            // juxtaposition is implicit AND
//   unary := NOT unary | primary
//   primary := ( or ) | comparison | text-term
//   comparison := field (=|!=|<|<=|>|>=) value
//               | field [NOT] IN (v, v…) | field LIKE v | field IS [NOT] NULL

// exprParser operates over a bounded token window.
type exprParser struct {
	toks []lexer.Token
	pos  int
}

func parseExprTokens(toks []lexer.Token) (*ast.Expr, error) {
	ep := &exprParser{toks: toks}
	e, err := ep.parseOr()
	if err != nil {
		return nil, err
	}
	if ep.cur().Kind != lexer.TokenEOF {
		return nil, fmt.Errorf("unexpected token %q at position %d", ep.cur().Raw, ep.cur().Pos)
	}
	return e, nil
}

func (ep *exprParser) cur() lexer.Token {
	if ep.pos >= len(ep.toks) {
		return lexer.Token{Kind: lexer.TokenEOF}
	}
	return ep.toks[ep.pos]
}
func (ep *exprParser) peek(n int) lexer.Token {
	i := ep.pos + n
	if i >= len(ep.toks) {
		return lexer.Token{Kind: lexer.TokenEOF}
	}
	return ep.toks[i]
}
func (ep *exprParser) advance() lexer.Token {
	t := ep.cur()
	ep.pos++
	return t
}

func (ep *exprParser) kw(word string, t lexer.Token) bool {
	return t.Kind == lexer.TokenName && strings.EqualFold(t.Value, word)
}

func (ep *exprParser) parseOr() (*ast.Expr, error) {
	left, err := ep.parseAnd()
	if err != nil {
		return nil, err
	}
	for ep.kw("or", ep.cur()) {
		ep.advance()
		right, err := ep.parseAnd()
		if err != nil {
			return nil, err
		}
		left = ast.Or(left, right)
	}
	return left, nil
}

func (ep *exprParser) parseAnd() (*ast.Expr, error) {
	left, err := ep.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		if ep.kw("and", ep.cur()) {
			ep.advance()
			right, err := ep.parseUnary()
			if err != nil {
				return nil, err
			}
			left = ast.And(left, right)
			continue
		}
		// Implicit AND by juxtaposition: next token starts a new operand
		// (not an operator/keyword/paren-close that ends the current one).
		if ep.startsOperand(ep.cur()) {
			right, err := ep.parseUnary()
			if err != nil {
				return nil, err
			}
			left = ast.And(left, right)
			continue
		}
		break
	}
	return left, nil
}

// startsOperand reports whether a token can begin a new boolean operand.
func (ep *exprParser) startsOperand(t lexer.Token) bool {
	switch t.Kind {
	case lexer.TokenName:
		if ep.kw("or", t) || ep.kw("and", t) || ep.kw("in", t) ||
			ep.kw("like", t) || ep.kw("is", t) || ep.kw("as", t) {
			return false
		}
		return true
	case lexer.TokenString, lexer.TokenNumber, lexer.TokenStar, lexer.TokenLParen:
		return true
	case lexer.TokenOp:
		// a leading NOT is an operand start (handled in unary via Name NOT too)
		return false
	default:
		return false
	}
}

func (ep *exprParser) parseUnary() (*ast.Expr, error) {
	if ep.kw("not", ep.cur()) {
		ep.advance()
		inner, err := ep.parseUnary()
		if err != nil {
			return nil, err
		}
		return ast.Not(inner), nil
	}
	return ep.parsePrimary()
}

func (ep *exprParser) parsePrimary() (*ast.Expr, error) {
	t := ep.cur()
	if t.Kind == lexer.TokenLParen {
		ep.advance()
		inner, err := ep.parseOr()
		if err != nil {
			return nil, err
		}
		if ep.cur().Kind != lexer.TokenRParen {
			return nil, fmt.Errorf("expected ')' at position %d", ep.cur().Pos)
		}
		ep.advance()
		return inner, nil
	}
	if ep.kw("not", t) {
		ep.advance()
		inner, err := ep.parseUnary()
		if err != nil {
			return nil, err
		}
		return ast.Not(inner), nil
	}
	return ep.parseComparison()
}

// parseComparison parses one predicate. field can be a Name token; a bare
// term (no operator follows) becomes a full-text term.
func (ep *exprParser) parseComparison() (*ast.Expr, error) {
	t := ep.cur()
	switch t.Kind {
	case lexer.TokenName:
		// Look ahead for comparison operator.
		if opTok, ok := ep.opAfter(1); ok {
			field := t.Value
			ep.advance() // field
			ep.advance() // op
			val, err := ep.readValue()
			if err != nil {
				return nil, err
			}
			return ast.Cmp(field, opTok, val), nil
		}
		// IN / NOT IN
		if ep.kw("in", ep.peek(1)) {
			field := t.Value
			ep.advance()
			ep.advance() // in
			return ep.readValueList(field, false)
		}
		if ep.kw("not", ep.peek(1)) && ep.kw("in", ep.peek(2)) {
			field := t.Value
			ep.advance() // field
			ep.advance() // not
			ep.advance() // in
			return ep.readValueList(field, true)
		}
		if ep.kw("like", ep.peek(1)) {
			field := t.Value
			ep.advance()
			ep.advance() // like
			val, err := ep.readValue()
			if err != nil {
				return nil, err
			}
			return ast.Like(field, false, val), nil
		}
		if ep.kw("is", ep.peek(1)) {
			field := t.Value
			ep.advance() // field
			ep.advance() // is
			neg := false
			if ep.kw("not", ep.cur()) {
				ep.advance()
				neg = true
			}
			if !ep.kw("null", ep.cur()) {
				return nil, fmt.Errorf("expected 'null' after IS at position %d", ep.cur().Pos)
			}
			ep.advance()
			return ast.IsNull(field, neg), nil
		}
		// Bare term: full-text search for the raw token (may include a
		// field=value with no spaces like "index=main" arriving as one name).
		raw := t.Value
		if opTok, v, ok := splitInlineAssignment(raw); ok {
			ep.advance()
			return ast.Cmp(opTok, "=", v), nil
		}
		ep.advance()
		return &ast.Expr{Kind: "text", Value: raw}, nil
	case lexer.TokenString:
		ep.advance()
		return &ast.Expr{Kind: "text", Value: t.Value, Pattern: t.Value, Negate: false}, nil
	case lexer.TokenNumber:
		ep.advance()
		return &ast.Expr{Kind: "text", Value: t.Value}, nil
	case lexer.TokenStar:
		ep.advance()
		return &ast.Expr{Kind: "text", Value: "*"}, nil
	default:
		return nil, fmt.Errorf("unexpected token %q at position %d", t.Raw, t.Pos)
	}
}

// opAfter reports whether the token n positions ahead is a comparison operator.
func (ep *exprParser) opAfter(n int) (string, bool) {
	t := ep.peek(n)
	if t.Kind != lexer.TokenOp {
		return "", false
	}
	switch t.Value {
	case "=", "!=", "<", "<=", ">", ">=":
		return t.Value, true
	}
	return "", false
}

// readValue consumes a single right-hand value (string, number, name, wildcard).
func (ep *exprParser) readValue() (string, error) {
	t := ep.cur()
	switch t.Kind {
	case lexer.TokenString:
		ep.advance()
		return t.Value, nil
	case lexer.TokenNumber, lexer.TokenName:
		ep.advance()
		return t.Value, nil
	case lexer.TokenStar:
		ep.advance()
		return "*", nil
	default:
		return "", fmt.Errorf("expected value at position %d", t.Pos)
	}
}

// readValueList parses "(v, v, …)" into an IN predicate.
func (ep *exprParser) readValueList(field string, negate bool) (*ast.Expr, error) {
	if ep.cur().Kind != lexer.TokenLParen {
		return nil, fmt.Errorf("expected '(' after IN at position %d", ep.cur().Pos)
	}
	ep.advance()
	var vals []string
	for {
		v, err := ep.readValue()
		if err != nil {
			return nil, err
		}
		vals = append(vals, v)
		if ep.cur().Kind == lexer.TokenComma {
			ep.advance()
			continue
		}
		break
	}
	if ep.cur().Kind != lexer.TokenRParen {
		return nil, fmt.Errorf("expected ')' after value list at position %d", ep.cur().Pos)
	}
	ep.advance()
	return ast.In(field, negate, vals...), nil
}

// splitInlineAssignment parses "key=value" arriving inside one name token
// (when there is no space around "="), returning field and value.
func splitInlineAssignment(s string) (field, val string, ok bool) {
	i := strings.Index(s, "=")
	if i <= 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// ───────────────────────────── commands ──────────────────────────────────

func parseSearch(p *Parser, toks []lexer.Token) (ast.Node, error) {
	sn := &ast.SearchNode{Fields: map[string]string{}}
	// Drop a leading explicit "search" if present.
	if len(toks) > 0 && toks[0].Kind == lexer.TokenName && strings.EqualFold(toks[0].Value, "search") {
		toks = toks[1:]
	}
	if len(toks) == 0 {
		return sn, nil
	}
	expr, err := parseExprTokens(toks)
	if err != nil {
		return nil, err
	}
	sn.Expr = flattenText(expr)
	// Classic flat projection: when the tree is a pure AND of field=value
	// equalities with no free text, populate Fields for the legacy planner.
	if fields, ok := flatFieldEquality(expr); ok {
		for k, v := range fields {
			sn.Fields[k] = v
		}
	}
	if text, ok := soleFreeText(expr); ok {
		sn.Text = text
	}
	return sn, nil
}

// flattenText keeps the general tree but normalises it; single-node passthrough.
func flattenText(e *ast.Expr) *ast.Expr { return e }

func soleFreeText(e *ast.Expr) (string, bool) {
	if e != nil && e.Kind == "text" {
		return e.Value, true
	}
	return "", false
}

// flatFieldEquality returns a key=value map when the entire expression is an
// AND (possibly single) of field "="/"value" comparisons and nothing else.
func flatFieldEquality(e *ast.Expr) (map[string]string, bool) {
	m := map[string]string{}
	var walk func(x *ast.Expr) bool
	walk = func(x *ast.Expr) bool {
		switch x.Kind {
		case "cmp":
			if x.Op == "=" && x.Field != "" {
				m[x.Field] = x.Value
				return true
			}
			return false
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
		return nil, false
	}
	return m, true
}

func parseWhere(p *Parser, toks []lexer.Token) (ast.Node, error) {
	expr, err := parseExprTokens(toks)
	if err != nil {
		return nil, err
	}
	wn := &ast.WhereNode{Expr: expr}
	if cs, ok := exprToConditionsClassic(expr); ok {
		wn.Conditions = cs
	}
	return wn, nil
}

func exprToConditionsClassic(e *ast.Expr) ([]ast.Condition, bool) {
	var out []ast.Condition
	var walk func(x *ast.Expr) bool
	walk = func(x *ast.Expr) bool {
		switch x.Kind {
		case "cmp":
			if x.Field == "" {
				return false
			}
			out = append(out, ast.Condition{Field: x.Field, Operator: x.Op, Value: x.Value})
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
		return nil, false
	}
	return out, true
}

func parseEval(p *Parser, toks []lexer.Token) (ast.Node, error) {
	if len(toks) == 0 {
		return nil, fmt.Errorf("eval requires an expression")
	}
	// Collect up to the first top-level "=" to name the field, rest is expr.
	field, rest := splitAtFirstEq(toks)
	if field == "" {
		return nil, fmt.Errorf("eval: expected field=expression")
	}
	// A bare string literal assignment (`status="failed"`) stores the decoded
	// value; string literals nested inside larger expressions keep their quotes
	// so the evaluator can tell literals from field references.
	var exprStr string
	if len(rest) == 1 && rest[0].Kind == lexer.TokenString {
		exprStr = rest[0].Value
	} else {
		exprStr = renderTokens(rest)
	}
	if exprStr == "" {
		return nil, fmt.Errorf("eval: empty expression for %s", field)
	}
	return &ast.EvalNode{Field: field, Expr: exprStr, Assignments: []ast.EvalAssignment{{Field: field, Expr: exprStr}}}, nil
}

// splitAtFirstEq returns the field name before the first top-level '=' op and
// the remaining tokens after it.
func splitAtFirstEq(toks []lexer.Token) (string, []lexer.Token) {
	depth := 0
	for i, t := range toks {
		if t.Kind == lexer.TokenLParen {
			depth++
		} else if t.Kind == lexer.TokenRParen {
			depth--
		} else if t.Kind == lexer.TokenOp && t.Value == "=" && depth == 0 {
			if i == 0 {
				return "", toks
			}
			return toks[i-1].Value, toks[i+1:]
		}
	}
	return "", toks
}

// renderTokens renders the token slice back into normalized SPL source for an
// eval expression, preserving operators/functions and string literals.
func renderTokens(toks []lexer.Token) string {
	parts := make([]string, 0, len(toks))
	for _, t := range toks {
		switch t.Kind {
		case lexer.TokenName:
			parts = append(parts, t.Value)
		case lexer.TokenNumber:
			parts = append(parts, t.Value)
		case lexer.TokenString:
			parts = append(parts, lexer.StringLiteral(t.Value))
		case lexer.TokenOp:
			parts = append(parts, t.Value)
		case lexer.TokenLParen:
			parts = append(parts, "(")
		case lexer.TokenRParen:
			parts = append(parts, ")")
		case lexer.TokenComma:
			parts = append(parts, ",")
		case lexer.TokenStar:
			parts = append(parts, "*")
		}
	}
	// Join tokens then normalise spacing: attach parentheses/commas, add
	// spaces around operators. This yields "count * 2", "round(x/1000, 2)".
	out := ""
	for i, tk := range toks {
		s := parts[i]
		switch tk.Kind {
		case lexer.TokenLParen:
			out += s
		case lexer.TokenRParen:
			out = strings.TrimRight(out, " ")
			out += s
		case lexer.TokenComma:
			out = strings.TrimRight(out, " ")
			out += ", "
		case lexer.TokenOp:
			if out != "" && !strings.HasSuffix(out, " ") {
				out += " "
			}
			out += s + " "
		default:
			if out != "" && !strings.HasSuffix(out, " ") && !strings.HasSuffix(out, "(") {
				out += " "
			}
			// function call: name immediately followed by '(' -> no space
			if tk.Kind == lexer.TokenName && i+1 < len(toks) && toks[i+1].Kind == lexer.TokenLParen {
				out += s
				continue
			}
			out += s
		}
	}
	return strings.TrimSpace(out)
}

func parseStats(p *Parser, toks []lexer.Token) (ast.Node, error) {
	node, err := parseAggregationNode(toks)
	if err != nil {
		return nil, err
	}
	return &ast.StatsNode{Aggs: node.aggs, GroupBy: node.groupby}, nil
}

type aggParseResult struct {
	aggs    []ast.Aggregation
	groupby []string
	span    string
	window  int
}

func parseAggregationNode(toks []lexer.Token) (aggParseResult, error) {
	// Split at top-level "by".
	byIdx := -1
	depth := 0
	for i, t := range toks {
		switch t.Kind {
		case lexer.TokenLParen:
			depth++
		case lexer.TokenRParen:
			depth--
		case lexer.TokenName:
			if depth == 0 && strings.EqualFold(t.Value, "by") {
				byIdx = i
			}
		}
	}
	var aggToks, groupToks []lexer.Token
	if byIdx >= 0 {
		aggToks = toks[:byIdx]
		groupToks = toks[byIdx+1:]
	} else {
		aggToks = toks
	}
	var res aggParseResult
	for _, t := range groupToks {
		if t.Kind == lexer.TokenComma {
			continue
		}
		if t.Kind == lexer.TokenName || t.Kind == lexer.TokenString {
			res.groupby = append(res.groupby, t.Value)
		}
	}
	// Parse aggregations: comma/space separated. Each: func[(field)][ as alias]
	for i := 0; i < len(aggToks); {
		t := aggToks[i]
		if t.Kind == lexer.TokenComma {
			i++
			continue
		}
		if t.Kind != lexer.TokenName {
			i++
			continue
		}
		fn := strings.ToLower(t.Value)
		field := ""
		i++
		// func(field)
		if i < len(aggToks) && aggToks[i].Kind == lexer.TokenLParen {
			i++ // (
			var fb []string
			for i < len(aggToks) && aggToks[i].Kind != lexer.TokenRParen {
				if aggToks[i].Kind == lexer.TokenStar {
					fb = append(fb, "*")
				} else if aggToks[i].Kind == lexer.TokenName || aggToks[i].Kind == lexer.TokenNumber {
					fb = append(fb, aggToks[i].Value)
				}
				i++
			}
			if i < len(aggToks) {
				i++ // )
			}
			field = strings.Join(fb, "")
		}
		// optional "as alias"
		alias := ""
		if i < len(aggToks) && aggToks[i].Kind == lexer.TokenName && strings.EqualFold(aggToks[i].Value, "as") {
			i++
			if i < len(aggToks) && (aggToks[i].Kind == lexer.TokenName || aggToks[i].Kind == lexer.TokenString) {
				alias = aggToks[i].Value
				i++
			}
		}
		if fn == "count" && field == "" {
			field = "*"
		}
		res.aggs = append(res.aggs, ast.Aggregation{Function: fn, Field: field, Alias: alias})
	}
	return res, nil
}

func parseTimechart(p *Parser, toks []lexer.Token) (ast.Node, error) {
	var span string
	// extract span=N
	var rest []lexer.Token
	for i := 0; i < len(toks); i++ {
		if toks[i].Kind == lexer.TokenName && strings.EqualFold(toks[i].Value, "span") &&
			i+1 < len(toks) && toks[i+1].Kind == lexer.TokenOp && toks[i+1].Value == "=" &&
			i+2 < len(toks) {
			span = toks[i+2].Value
			i += 2
			continue
		}
		rest = append(rest, toks[i])
	}
	node, err := parseAggregationNode(rest)
	if err != nil {
		return nil, err
	}
	fn := ast.Aggregation{Function: "count", Field: "*"}
	if len(node.aggs) > 0 {
		fn = node.aggs[0]
		if fn.Field == "" {
			fn.Field = "*"
		}
	}
	return &ast.TimechartNode{Func: fn, Span: span, GroupBy: node.groupby}, nil
}

func parseSort(p *Parser, toks []lexer.Token) (ast.Node, error) {
	node := &ast.SortNode{}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.Kind == lexer.TokenName && strings.EqualFold(t.Value, "by") {
			continue
		}
		desc := false
		// leading - indicates desc
		if t.Kind == lexer.TokenOp && t.Value == "-" && i+1 < len(toks) && toks[i+1].Kind == lexer.TokenName {
			desc = true
			node.Fields = append(node.Fields, ast.SortField{Field: toks[i+1].Value, Desc: desc})
			i++
			continue
		}
		if t.Kind == lexer.TokenName {
			if _, err := strconv.Atoi(t.Value); err == nil {
				continue // numeric sort limit arg (e.g. sort 100 field)
			}
			node.Fields = append(node.Fields, ast.SortField{Field: t.Value, Desc: false})
		}
	}
	if len(node.Fields) == 0 {
		return nil, fmt.Errorf("sort requires at least one field")
	}
	return node, nil
}

func parseHead(p *Parser, toks []lexer.Token) (ast.Node, error) {
	n, err := parseCount(toks)
	if err != nil {
		return nil, fmt.Errorf("head: %w", err)
	}
	return &ast.HeadNode{N: n}, nil
}

func parseTail(p *Parser, toks []lexer.Token) (ast.Node, error) {
	n, err := parseCount(toks)
	if err != nil {
		return nil, fmt.Errorf("tail: %w", err)
	}
	return &ast.TailNode{N: n}, nil
}

func parseCount(toks []lexer.Token) (int, error) {
	for _, t := range toks {
		if t.Kind == lexer.TokenNumber {
			return strconv.Atoi(t.Value)
		}
	}
	return 0, fmt.Errorf("requires a number argument")
}

func parseDedup(p *Parser, toks []lexer.Token) (ast.Node, error) {
	for _, t := range toks {
		if t.Kind == lexer.TokenName {
			if _, err := strconv.Atoi(t.Value); err == nil {
				continue // dedup limit arg
			}
			return &ast.DedupNode{Field: t.Value}, nil
		}
	}
	return nil, fmt.Errorf("dedup requires a field name")
}

func parseFields(p *Parser, toks []lexer.Token) (ast.Node, error) {
	include := true
	var fields []string
	for i, t := range toks {
		if t.Kind == lexer.TokenOp && t.Value == "-" && i == 0 {
			include = false
			continue
		}
		if t.Kind == lexer.TokenOp && t.Value == "+" && i == 0 {
			include = true
			continue
		}
		if t.Kind == lexer.TokenComma {
			continue
		}
		if t.Kind == lexer.TokenName || t.Kind == lexer.TokenString {
			f := t.Value
			f = strings.TrimPrefix(f, "-")
			f = strings.TrimPrefix(f, "+")
			if f != "" {
				fields = append(fields, f)
			}
		}
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("fields requires at least one field")
	}
	return &ast.FieldsNode{Include: include, Fields: fields}, nil
}

func parseTable(p *Parser, toks []lexer.Token) (ast.Node, error) {
	var fields []string
	for _, t := range toks {
		if t.Kind == lexer.TokenComma {
			continue
		}
		if t.Kind == lexer.TokenName || t.Kind == lexer.TokenString {
			fields = append(fields, t.Value)
		} else if t.Kind == lexer.TokenStar {
			fields = append(fields, "*")
		}
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("table requires at least one field")
	}
	return &ast.TableNode{Fields: fields}, nil
}

func parseRename(p *Parser, toks []lexer.Token) (ast.Node, error) {
	rn := &ast.RenameNode{Mappings: map[string]string{}}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.Kind == lexer.TokenComma {
			continue
		}
		if t.Kind != lexer.TokenName {
			continue
		}
		from := t.Value
		// expect optional "as to"
		if i+2 < len(toks) && toks[i+1].Kind == lexer.TokenName && strings.EqualFold(toks[i+1].Value, "as") {
			to := toks[i+2].Value
			rn.Mappings[from] = to
			rn.MappingsOrdered = append(rn.MappingsOrdered, ast.RenamePair{From: from, To: to})
			i += 2
			continue
		}
		return nil, fmt.Errorf("rename: expected 'old as new' near %q", from)
	}
	if len(rn.Mappings) == 0 {
		return nil, fmt.Errorf("rename requires at least one mapping")
	}
	return rn, nil
}

func parseRex(p *Parser, toks []lexer.Token) (ast.Node, error) {
	node := &ast.RexNode{}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.Kind == lexer.TokenName && i+2 < len(toks) && toks[i+1].Kind == lexer.TokenOp && toks[i+1].Value == "=" {
			key := strings.ToLower(t.Value)
			valTok := toks[i+2]
			val := valTok.Value
			switch key {
			case "field":
				node.Field = val
			case "rename", "alias":
				node.Rename = val
			case "mode":
				node.Mode = val
			}
			i += 2
			continue
		}
		if t.Kind == lexer.TokenString {
			node.Pattern = t.Value
		} else if t.Kind == lexer.TokenName && node.Pattern == "" {
			// unquoted pattern fallback
			node.Pattern = t.Value
		}
	}
	if node.Pattern == "" {
		return nil, fmt.Errorf("rex requires a pattern")
	}
	return node, nil
}

func parseBin(p *Parser, toks []lexer.Token) (ast.Node, error) {
	node := &ast.BinNode{}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.Kind == lexer.TokenName && i+2 < len(toks) && toks[i+1].Kind == lexer.TokenOp && toks[i+1].Value == "=" && strings.EqualFold(t.Value, "span") {
			node.Span = toks[i+2].Value
			i += 2
			continue
		}
		if t.Kind == lexer.TokenName && node.Field == "" {
			node.Field = t.Value
		}
	}
	if node.Field == "" {
		return nil, fmt.Errorf("bin requires a field")
	}
	return node, nil
}

func parseLookup(p *Parser, toks []lexer.Token) (ast.Node, error) {
	node := &ast.LookupNode{}
	// lookup <table> <inputfield> [OUTPUT out..] [APPEND]
	var words []string
	for _, t := range toks {
		if t.Kind == lexer.TokenName {
			words = append(words, t.Value)
		} else if t.Kind == lexer.TokenString {
			words = append(words, t.Value)
		}
	}
	if len(words) < 2 {
		return nil, fmt.Errorf("lookup requires a lookup name and an input field")
	}
	for _, w := range words {
		switch strings.ToUpper(w) {
		case "OUTPUT", "OUTPUTNEW", "OUTPUTAPPEND":
			continue
		case "APPEND":
			node.Append = true
		default:
			if node.Lookup == "" {
				node.Lookup = w
			} else if node.InputField == "" && !node.Append {
				node.InputField = w
			} else {
				node.OutputFields = append(node.OutputFields, w)
			}
		}
	}
	return node, nil
}

func parseEventstats(p *Parser, toks []lexer.Token) (ast.Node, error) {
	node, err := parseAggregationNode(toks)
	if err != nil {
		return nil, err
	}
	return &ast.EventstatsNode{Aggs: node.aggs, GroupBy: node.groupby}, nil
}

func parseStreamstats(p *Parser, toks []lexer.Token) (ast.Node, error) {
	var window int
	var rest []lexer.Token
	for i := 0; i < len(toks); i++ {
		if toks[i].Kind == lexer.TokenName && strings.EqualFold(toks[i].Value, "window") &&
			i+2 < len(toks) && toks[i+1].Kind == lexer.TokenOp && toks[i+1].Value == "=" {
			window, _ = strconv.Atoi(toks[i+2].Value)
			i += 2
			continue
		}
		rest = append(rest, toks[i])
	}
	node, err := parseAggregationNode(rest)
	if err != nil {
		return nil, err
	}
	return &ast.StreamstatsNode{Aggs: node.aggs, GroupBy: node.groupby, Window: window}, nil
}
