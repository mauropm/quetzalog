// Package lexer turns SPL text into a token stream for the parser. It is a
// deliberately hand-written scanner (no regexp backtracking) so that pathological
// inputs cannot cause catastrophic behaviour, and it understands quoted strings,
// escapes, numbers (incl. negatives/decimals), function names, parentheses and
// the full operator set used by SPL.
package lexer

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// TokenKind classifies a token.
type TokenKind int

const (
	TokenName TokenKind = iota
	TokenString
	TokenNumber
	TokenOp
	TokenLParen
	TokenRParen
	TokenPipe
	TokenComma
	TokenStar
	TokenEOF
)

func (k TokenKind) String() string {
	switch k {
	case TokenName:
		return "name"
	case TokenString:
		return "string"
	case TokenNumber:
		return "number"
	case TokenOp:
		return "operator"
	case TokenLParen:
		return "("
	case TokenRParen:
		return ")"
	case TokenPipe:
		return "|"
	case TokenComma:
		return ","
	case TokenStar:
		return "*"
	case TokenEOF:
		return "end of query"
	}
	return "token"
}

// Token is a lexed SPL token.
type Token struct {
	Kind  TokenKind
	Value string // raw text (operators/numbers/names), decoded content for strings
	Raw   string // original text incl. quotes (strings), == Value otherwise
	Quote rune   // quote char for strings (0 otherwise)
	Pos   int
}

func (t Token) IsKeyword(word string) bool {
	return t.Kind == TokenName && strings.EqualFold(t.Value, word)
}

// Lexer scans an input string.
type Lexer struct {
	input []rune
	pos   int
}

// NewLexer allocates a lexer over input.
func NewLexer(input string) *Lexer {
	return &Lexer{input: []rune(input)}
}

// Tokenize scans the whole input into a token slice (terminated by EOF).
func Tokenize(input string) ([]Token, error) {
	l := NewLexer(input)
	var out []Token
	for {
		t := l.Next()
		out = append(out, t)
		if t.Kind == TokenEOF {
			break
		}
		if t.Kind == TokenOp && t.Value == "" {
			return nil, fmt.Errorf("unexpected character %q at position %d", t.Raw, t.Pos)
		}
	}
	return out, nil
}

func (l *Lexer) Next() Token {
	l.skipSpace()
	if l.pos >= len(l.input) {
		return Token{Kind: TokenEOF, Pos: l.pos}
	}
	start := l.pos
	ch := l.input[l.pos]

	switch ch {
	case '|':
		l.pos++
		return Token{Kind: TokenPipe, Value: "|", Raw: "|", Pos: start}
	case ',':
		l.pos++
		return Token{Kind: TokenComma, Value: ",", Raw: ",", Pos: start}
	case '(':
		l.pos++
		return Token{Kind: TokenLParen, Value: "(", Raw: "(", Pos: start}
	case ')':
		l.pos++
		return Token{Kind: TokenRParen, Value: ")", Raw: ")", Pos: start}
	case '*':
		l.pos++
		return Token{Kind: TokenStar, Value: "*", Raw: "*", Pos: start}
	case '"', '\'':
		return l.scanString(ch, start)
	}

	// Numbers and (possibly negative) numeric literals.
	if isDigit(ch) {
		return l.scanNumber(start)
	}
	if ch == '-' && l.pos+1 < len(l.input) && (isDigit(l.input[l.pos+1]) || l.input[l.pos+1] == '.') {
		if l.prevAllowsNegative() {
			return l.scanNumber(start)
		}
	}

	if isNameStart(ch) {
		return l.scanName(start)
	}

	return l.scanOperator(start)
}

func (l *Lexer) skipSpace() {
	for l.pos < len(l.input) {
		if unicode.IsSpace(l.input[l.pos]) {
			l.pos++
			continue
		}
		break
	}
}

func (l *Lexer) scanString(quote rune, start int) Token {
	l.pos++ // opening quote
	var b strings.Builder
	for l.pos < len(l.input) {
		ch := l.input[l.pos]
		if ch == '\\' && l.pos+1 < len(l.input) {
			nxt := l.input[l.pos+1]
			// Only the active quote and a literal backslash are unescaped.
			// Everything else (regex classes such as \d, \., \s, …) is kept
			// verbatim so regular expressions survive round-tripping.
			if nxt == quote || nxt == '\\' {
				b.WriteRune(nxt)
				l.pos += 2
				continue
			}
			b.WriteRune('\\')
			l.pos++
			continue
		}
		if ch == quote {
			l.pos++
			return Token{Kind: TokenString, Value: b.String(), Raw: string(l.input[start:l.pos]), Quote: quote, Pos: start}
		}
		b.WriteRune(ch)
		l.pos++
	}
	// Unterminated string: take to end (parser will treat as literal text).
	return Token{Kind: TokenString, Value: b.String(), Raw: string(l.input[start:l.pos]), Quote: quote, Pos: start}
}

func (l *Lexer) scanNumber(start int) Token {
	for l.pos < len(l.input) {
		ch := l.input[l.pos]
		if isDigit(ch) || ch == '.' {
			l.pos++
			continue
		}
		if (ch == 'e' || ch == 'E') && l.pos+1 < len(l.input) {
			nn := l.input[l.pos+1]
			if isDigit(nn) || ((nn == '+' || nn == '-') && l.pos+2 < len(l.input) && isDigit(l.input[l.pos+2])) {
				l.pos++
				if nn == '+' || nn == '-' {
					l.pos++
				}
				continue
			}
		}
		break
	}
	return Token{Kind: TokenNumber, Value: string(l.input[start:l.pos]), Raw: string(l.input[start:l.pos]), Pos: start}
}

func (l *Lexer) scanName(start int) Token {
	for l.pos < len(l.input) {
		ch := l.input[l.pos]
		if isNamePart(ch) {
			l.pos++
			continue
		}
		break
	}
	return Token{Kind: TokenName, Value: string(l.input[start:l.pos]), Raw: string(l.input[start:l.pos]), Pos: start}
}

func (l *Lexer) scanOperator(start int) Token {
	two := ""
	if l.pos+1 < len(l.input) {
		two = string(l.input[l.pos : l.pos+2])
	}
	switch two {
	case "!=":
		l.pos += 2
		return Token{Kind: TokenOp, Value: "!=", Raw: "!=", Pos: start}
	case "<>":
		l.pos += 2
		return Token{Kind: TokenOp, Value: "!=", Raw: "<>", Pos: start}
	case "==":
		l.pos += 2
		return Token{Kind: TokenOp, Value: "=", Raw: "==", Pos: start}
	case ">=":
		l.pos += 2
		return Token{Kind: TokenOp, Value: ">=", Raw: ">=", Pos: start}
	case "<=":
		l.pos += 2
		return Token{Kind: TokenOp, Value: "<=", Raw: "<=", Pos: start}
	}
	ch := l.input[l.pos]
	switch ch {
	case '=', '<', '>':
		l.pos++
		return Token{Kind: TokenOp, Value: string(ch), Raw: string(ch), Pos: start}
	case '+', '-', '/', '%', '&':
		l.pos++
		return Token{Kind: TokenOp, Value: string(ch), Raw: string(ch), Pos: start}
	}
	// Unknown single character surfaced as an empty op so Tokenize reports it.
	l.pos++
	return Token{Kind: TokenOp, Value: "", Raw: string(ch), Pos: start}
}

// prevAllowsNegative reports whether a '-' at the current position begins a
// negative number (i.e. it follows an operator/paren/comma/start, not a value).
func (l *Lexer) prevAllowsNegative() bool {
	for i := l.pos - 1; i >= 0; i-- {
		c := l.input[i]
		if unicode.IsSpace(c) {
			continue
		}
		switch c {
		case '(', ',', '|', '=', '!', '<', '>', '+', '-', '*', '/', '%', '&':
			return true
		}
		return false
	}
	return true // start of input
}

func isDigit(ch rune) bool   { return ch >= '0' && ch <= '9' }
func isNameStart(ch rune) bool {
	return unicode.IsLetter(ch) || ch == '_' || ch == '@' || ch == ':'
}
func isNamePart(ch rune) bool {
	return unicode.IsLetter(ch) || unicode.IsDigit(ch) || ch == '_' || ch == '.' ||
		ch == '@' || ch == ':' || ch == '-'
}

// StringLiteral renders a Go string as a double-quoted SPL string literal.
func StringLiteral(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, ch := range s {
		switch ch {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(ch)
		}
	}
	b.WriteByte('"')
	return b.String()
}

var _ = utf8.RuneError
