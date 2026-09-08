package lexer

import "unicode/utf8"

type TokenType int

const (
	UNKNOWN TokenType = iota
	IDENT
	STRING
	NUMBER
	OP
	PIPE
	COMMA
	STAR
	MINUS
	EOF
)

type Token struct {
	Type  TokenType
	Value string
}

type Lexer struct {
	input string
	pos   int
}

func NewLexer(input string) *Lexer {
	return &Lexer{
		input: input,
		pos:   0,
	}
}

func (l *Lexer) NextToken() Token {
	l.skipWhitespace()

	if l.pos >= len(l.input) {
		return Token{Type: EOF, Value: ""}
	}

	ch := l.read()

	switch ch {
	case '|':
		return Token{Type: PIPE, Value: "|"}
	case ',':
		return Token{Type: COMMA, Value: ","}
	case '*':
		return Token{Type: STAR, Value: "*"}
	case '-':
		return Token{Type: MINUS, Value: "-"}
	case '=':
		return Token{Type: OP, Value: "="}
	case '!':
		if l.peek() == '=' {
			l.read()
			return Token{Type: OP, Value: "!="}
		}
		return Token{Type: UNKNOWN, Value: string(ch)}
	case '>':
		if l.peek() == '=' {
			l.read()
			return Token{Type: OP, Value: ">="}
		}
		return Token{Type: OP, Value: ">"}
	case '<':
		if l.peek() == '=' {
			l.read()
			return Token{Type: OP, Value: "<="}
		}
		return Token{Type: OP, Value: "<"}
	}

	if ch == '\'' || ch == '"' {
		return l.readString(ch)
	}

	if unicodeIsDigit(ch) {
		l.unread()
		return l.readNumber()
	}

	if unicodeIsLetter(ch) || ch == '_' || ch == '.' {
		l.unread()
		return l.readIdentifier()
	}

	return Token{Type: UNKNOWN, Value: string(ch)}
}

func (l *Lexer) skipWhitespace() {
	for l.pos < len(l.input) {
		ch := l.peek()
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			l.pos++
		} else {
			break
		}
	}
}

func (l *Lexer) read() rune {
	if l.pos >= len(l.input) {
		return utf8.RuneError
	}
	ch, size := utf8.DecodeRuneInString(l.input[l.pos:])
	l.pos += size
	return ch
}

func (l *Lexer) peek() rune {
	if l.pos >= len(l.input) {
		return utf8.RuneError
	}
	ch, _ := utf8.DecodeRuneInString(l.input[l.pos:])
	return ch
}

func (l *Lexer) unread() {
	l.pos--
}

func (l *Lexer) readUntil(char rune) string {
	start := l.pos
	for l.pos < len(l.input) {
		ch, size := utf8.DecodeRuneInString(l.input[l.pos:])
		l.pos += size
		if ch == char {
			break
		}
	}
	return l.input[start:l.pos]
}

func (l *Lexer) readString(quote rune) Token {
	start := l.pos
	for l.pos < len(l.input) {
		ch, size := utf8.DecodeRuneInString(l.input[l.pos:])
		l.pos += size
		if ch == quote {
			return Token{
				Type:  STRING,
				Value: l.input[start : l.pos-1],
			}
		}
	}
	return Token{Type: STRING, Value: l.input[start:]}
}

func (l *Lexer) readNumber() Token {
	start := l.pos
	for l.pos < len(l.input) {
		ch := l.peek()
		if unicodeIsDigit(ch) {
			l.read()
		} else {
			break
		}
	}
	return Token{
		Type:  NUMBER,
		Value: l.input[start:l.pos],
	}
}

func (l *Lexer) readIdentifier() Token {
	start := l.pos
	for l.pos < len(l.input) {
		ch := l.peek()
		if unicodeIsLetter(ch) || unicodeIsDigit(ch) || ch == '_' || ch == '.' || ch == '-' || ch == '/' {
			l.read()
		} else {
			break
		}
	}
	return Token{
		Type:  IDENT,
		Value: l.input[start:l.pos],
	}
}

func unicodeIsDigit(ch rune) bool {
	return ch >= '0' && ch <= '9'
}

func unicodeIsLetter(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}
