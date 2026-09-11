package executor

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"quetzalog/internal/spl/ast"
	"quetzalog/internal/spl/lexer"
)

// EvalEvaluator evaluates SPL eval expressions against an in-memory event.
type EvalEvaluator struct{}

// NewEvalEvaluator constructs an evaluator.
func NewEvalEvaluator() (*EvalEvaluator, error) { return &EvalEvaluator{}, nil }

// EvalExpr evaluates a single expression string.
func (e *EvalEvaluator) EvalExpr(event map[string]any, expr string) any {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return ""
	}
	// Fast path: bare string literal.
	if len(expr) >= 2 && (expr[0] == '"' || expr[0] == '\'') {
		if t, err := lexer.Tokenize(expr); err == nil && len(t) >= 2 && t[0].Kind == lexer.TokenString {
			return t[0].Value
		}
	}
	// Fast path: bare field reference.
	if isBareIdent(expr) {
		if v, ok := lookupField(event, expr); ok {
			return v
		}
		if f, err := strconv.ParseFloat(expr, 64); err == nil {
			return f
		}
		return expr // unresolved identifier behaves as a literal
	}
	toks, err := lexer.Tokenize(expr)
	if err != nil || len(toks) == 0 {
		return expr
	}
	te := &tokEval{toks: toks, ev: e}
	val := te.parseExpr(event)
	return val
}

// TransformEval applies all eval assignments in the nodes to the batch.
func (e *EvalEvaluator) TransformEval(events []map[string]any, nodes []ast.Node) {
	for _, node := range nodes {
		en, ok := node.(*ast.EvalNode)
		if !ok {
			continue
		}
		asg := en.Assignments
		if len(asg) == 0 && en.Field != "" {
			asg = []ast.EvalAssignment{{Field: en.Field, Expr: en.Expr}}
		}
		for _, a := range asg {
			for i := range events {
				events[i][a.Field] = e.EvalExpr(events[i], a.Expr)
			}
		}
	}
}

// TransformRex extracts named regex groups into fields on the event.
func (e *EvalEvaluator) TransformRex(event map[string]any, node *ast.RexNode) error {
	if node.Pattern == "" {
		return nil
	}
	re, err := regexp.Compile(node.Pattern)
	if err != nil {
		return fmt.Errorf("compile regex: %w", err)
	}
	srcField := node.Field
	if srcField == "" || srcField == "_raw" {
		srcField = "raw"
		if _, ok := event["raw"]; !ok {
			srcField = "message"
		}
	}
	input, ok := event[srcField].(string)
	if !ok {
		input = fmt.Sprintf("%v", event[srcField])
	}
	match := re.FindStringSubmatch(input)
	if match == nil {
		return nil
	}
	names := re.SubexpNames()
	var first string
	for i := 1; i < len(names); i++ {
		name := names[i]
		if name == "" {
			continue
		}
		if first == "" {
			first = name
		}
		val := match[i]
		if node.Mode == "multimatch" {
			if ex, ok := event[name].([]string); ok {
				event[name] = append(ex, val)
			} else {
				event[name] = []string{val}
			}
		} else {
			event[name] = val
		}
	}
	if node.Rename != "" && first != "" {
		event[node.Rename] = event[first]
		if first != node.Rename {
			delete(event, first)
		}
	}
	return nil
}

// ───────────────────────── token expression evaluator ───────────────────────
type tokEval struct {
	toks []lexer.Token
	pos  int
	ev   *EvalEvaluator
}

func (t *tokEval) cur() lexer.Token {
	if t.pos >= len(t.toks) {
		return lexer.Token{Kind: lexer.TokenEOF}
	}
	return t.toks[t.pos]
}
func (t *tokEval) next() { t.pos++ }
func (t *tokEval) isKw(w string) bool {
	tk := t.cur()
	return tk.Kind == lexer.TokenName && strings.EqualFold(tk.Value, w)
}

func (t *tokEval) parseExpr(ev map[string]any) any { return t.parseOr(ev) }

func (t *tokEval) parseOr(ev map[string]any) any {
	left := t.parseAnd(ev)
	for t.isKw("or") {
		t.next()
		right := t.parseAnd(ev)
		left = toBool(left) || toBool(right)
	}
	return left
}
func (t *tokEval) parseAnd(ev map[string]any) any {
	left := t.parseNot(ev)
	for t.isKw("and") {
		t.next()
		right := t.parseNot(ev)
		left = toBool(left) && toBool(right)
	}
	return left
}
func (t *tokEval) parseNot(ev map[string]any) any {
	if t.isKw("not") {
		t.next()
		return !toBool(t.parseNot(ev))
	}
	return t.parseCmp(ev)
}

func (t *tokEval) parseCmp(ev map[string]any) any {
	left := t.parseAdd(ev)
	tk := t.cur()
	if tk.Kind == lexer.TokenOp {
		switch tk.Value {
		case "=", "==", "!=", "<", "<=", ">", ">=":
			op := tk.Value
			if op == "==" {
				op = "="
			}
			t.next()
			right := t.parseAdd(ev)
			return compare(op, left, right)
		}
	}
	return left
}

func (t *tokEval) parseAdd(ev map[string]any) any {
	left := t.parseMul(ev)
	for {
		tk := t.cur()
		if tk.Kind == lexer.TokenOp && (tk.Value == "+" || tk.Value == "-" || tk.Value == "%") {
			op := tk.Value
			t.next()
			right := t.parseMul(ev)
			left = arith(op, left, right)
			continue
		}
		break
	}
	return left
}
func (t *tokEval) parseMul(ev map[string]any) any {
	left := t.parseUnary(ev)
	for {
		tk := t.cur()
		if tk.Value == "*" || tk.Value == "/" {
			if tk.Kind == lexer.TokenOp || tk.Kind == lexer.TokenStar {
				op := tk.Value
				t.next()
				right := t.parseUnary(ev)
				left = arith(op, left, right)
				continue
			}
		}
		break
	}
	return left
}
func (t *tokEval) parseUnary(ev map[string]any) any {
	tk := t.cur()
	if tk.Kind == lexer.TokenOp && tk.Value == "-" {
		t.next()
		v := toFloat(t.parseUnary(ev))
		return -v
	}
	if tk.Kind == lexer.TokenOp && tk.Value == "+" {
		t.next()
		return t.parseUnary(ev)
	}
	return t.parsePrimary(ev)
}

func (t *tokEval) parsePrimary(ev map[string]any) any {
	tk := t.cur()
	switch tk.Kind {
	case lexer.TokenLParen:
		t.next()
		v := t.parseExpr(ev)
		if t.cur().Kind == lexer.TokenRParen {
			t.next()
		}
		return v
	case lexer.TokenNumber:
		t.next()
		f, _ := strconv.ParseFloat(tk.Value, 64)
		return f
	case lexer.TokenString:
		t.next()
		return tk.Value
	case lexer.TokenName:
		name := tk.Value
		t.next()
		if t.cur().Kind == lexer.TokenLParen {
			return t.callFunction(strings.ToLower(name), ev)
		}
		if v, ok := lookupField(ev, name); ok {
			return v
		}
		if f, err := strconv.ParseFloat(name, 64); err == nil {
			return f
		}
		return name // literal fallback
	case lexer.TokenStar:
		t.next()
		return "*"
	default:
		t.next()
		return nil
	}
}

func (t *tokEval) callFunction(name string, ev map[string]any) any {
	if t.cur().Kind == lexer.TokenLParen {
		t.next()
	}
	var args []any
	for t.cur().Kind != lexer.TokenRParen && t.cur().Kind != lexer.TokenEOF {
		args = append(args, t.parseExpr(ev))
		if t.cur().Kind == lexer.TokenComma {
			t.next()
		} else {
			break
		}
	}
	if t.cur().Kind == lexer.TokenRParen {
		t.next()
	}
	return callFunction(name, args)
}

func callFunction(name string, args []any) any {
	switch name {
	case "if":
		if len(args) >= 1 && toBool(args[0]) {
			return arg(args, 1)
		}
		return arg(args, 2)
	case "case":
		for i := 0; i+1 < len(args); i += 2 {
			if toBool(args[i]) {
				return args[i+1]
			}
		}
		return nil
	case "coalesce":
		for _, a := range args {
			if a != nil && a != "" {
				return a
			}
		}
		return ""
	case "len":
		return float64(len(fmt.Sprintf("%v", arg(args, 0))))
	case "lower":
		return strings.ToLower(fmt.Sprintf("%v", arg(args, 0)))
	case "upper":
		return strings.ToUpper(fmt.Sprintf("%v", arg(args, 0)))
	case "substr":
		s := fmt.Sprintf("%v", arg(args, 0))
		start := int(toFloat(arg(args, 1)))
		if start < 0 {
			start = 0
		}
		if start >= len(s) {
			return ""
		}
		if len(args) >= 3 {
			l := int(toFloat(args[2]))
			if start+l > len(s) {
				l = len(s) - start
			}
			return s[start : start+l]
		}
		return s[start:]
	case "replace":
		if len(args) < 3 {
			return arg(args, 0)
		}
		return strings.ReplaceAll(fmt.Sprintf("%v", args[0]), fmt.Sprintf("%v", args[1]), fmt.Sprintf("%v", args[2]))
	case "round":
		v := toFloat(arg(args, 0))
		places := int(toFloat(arg(args, 1)))
		round := 1.0
		for i := 0; i < places; i++ {
			round *= 10
		}
		return float64(int64(v*round+sign(v)*0.5)) / round
	case "tonumber":
		f, err := strconv.ParseFloat(strings.TrimSpace(fmt.Sprintf("%v", arg(args, 0))), 64)
		if err != nil {
			return nil
		}
		return f
	case "tostring":
		if len(args) >= 2 && fmt.Sprintf("%v", args[1]) == "hex" {
			return fmt.Sprintf("%x", int64(toFloat(args[0])))
		}
		return fmt.Sprintf("%v", arg(args, 0))
	case "isnull":
		v := arg(args, 0)
		return v == nil || v == ""
	case "isnotnull":
		v := arg(args, 0)
		return !(v == nil || v == "")
	case "now":
		return float64(time.Now().Unix())
	case "abs":
		return fabs(toFloat(arg(args, 0)))
	case "ceil":
		return fceil(toFloat(arg(args, 0)))
	case "floor":
		return ffloor(toFloat(arg(args, 0)))
	case "sqrt":
		return fsqrt(toFloat(arg(args, 0)))
	case "log":
		return flog(toFloat(arg(args, 0)))
	case "exp":
		return fexp(toFloat(arg(args, 0)))
	case "max":
		best := toFloat(args[0])
		for _, a := range args[1:] {
			if f := toFloat(a); f > best {
				best = f
			}
		}
		return best
	case "min":
		best := toFloat(args[0])
		for _, a := range args[1:] {
			if f := toFloat(a); f < best {
				best = f
			}
		}
		return best
	case "md5", "sha1", "sha256", "sha512":
		return fmt.Sprintf("%v", arg(args, 0))
	case "urldecode":
		return fmt.Sprintf("%v", arg(args, 0))
	case "trim":
		return strings.TrimSpace(fmt.Sprintf("%v", arg(args, 0)))
	case "ltrim":
		return strings.TrimLeft(fmt.Sprintf("%v", arg(args, 0)), " ")
	case "rtrim":
		return strings.TrimRight(fmt.Sprintf("%v", arg(args, 0)), " ")
	case "spath":
		return nil
	default:
		return nil
	}
}

func arg(args []any, i int) any {
	if i < len(args) {
		return args[i]
	}
	return nil
}

func lookupField(event map[string]any, key string) (any, bool) {
	if v, ok := event[key]; ok {
		return v, true
	}
	if v, ok := event[strings.ToLower(key)]; ok {
		return v, true
	}
	return nil, false
}

func isBareIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, ch := range s {
		if i == 0 && (ch == '_' || ch == '.') {
			continue
		}
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '.') {
			return false
		}
	}
	return true
}

func toFloat(v any) float64 {
	switch x := v.(type) {
	case nil:
		return 0
	case float64:
		return x
	case float32:
		return float64(x)
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case int32:
		return float64(x)
	case bool:
		if x {
			return 1
		}
		return 0
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f
	case []byte:
		f, _ := strconv.ParseFloat(strings.TrimSpace(string(x)), 64)
		return f
	default:
		return 0
	}
}

func toBool(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		s := strings.ToLower(x)
		return s != "" && s != "false" && s != "0" && s != "no"
	default:
		return toFloat(v) != 0
	}
}

func compare(op string, a, b any) bool {
	// string comparison when both sides look textual
	as, aStr := a.(string)
	bs, bStr := b.(string)
	if aStr && bStr {
		return cmpStr(op, as, bs)
	}
	if ab, ok := a.(bool); ok {
		return cmpBool(op, ab, toBool(b))
	}
	if bb, ok := b.(bool); ok {
		return cmpBool(op, toBool(a), bb)
	}
	af, bf := toFloat(a), toFloat(b)
	switch op {
	case "=", "==":
		return af == bf
	case "!=":
		return af != bf
	case "<":
		return af < bf
	case "<=":
		return af <= bf
	case ">":
		return af > bf
	case ">=":
		return af >= bf
	}
	return false
}

func cmpStr(op, a, b string) bool {
	switch op {
	case "=", "==":
		return a == b
	case "!=":
		return a != b
	case "<":
		return a < b
	case "<=":
		return a <= b
	case ">":
		return a > b
	case ">=":
		return a >= b
	}
	return false
}
func cmpBool(op string, a, b bool) bool {
	switch op {
	case "=", "==":
		return a == b
	case "!=":
		return a != b
	}
	return false
}

func arith(op string, a, b any) any {
	af, bf := toFloat(a), toFloat(b)
	switch op {
	case "+":
		// string concatenation when either operand is non-numeric text
		if looksText(a) || looksText(b) {
			if _, ok := a.(string); ok || !isNumericStr(a) {
				if !isNumericStr(a) && !isNumericStr(b) {
					return fmt.Sprintf("%v%v", a, b)
				}
			}
		}
		return af + bf
	case "-":
		return af - bf
	case "*":
		return af * bf
	case "/":
		if bf == 0 {
			return 0
		}
		return af / bf
	case "%":
		if bf == 0 {
			return 0
		}
		return float64(int64(af) % int64(bf))
	}
	return af

}

func looksText(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	_, err := strconv.ParseFloat(s, 64)
	return err != nil
}
func isNumericStr(v any) bool {
	s, ok := v.(string)
	if !ok {
		return true
	}
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

func sign(f float64) float64 {
	if f < 0 {
		return -1
	}
	return 1
}

func fabs(f float64) float64  { return math.Abs(f) }
func fceil(f float64) float64  { return math.Ceil(f) }
func ffloor(f float64) float64 { return math.Floor(f) }
func fsqrt(f float64) float64  { return math.Sqrt(f) }
func flog(f float64) float64   { return math.Log(f) }
func fexp(f float64) float64   { return math.Exp(f) }
