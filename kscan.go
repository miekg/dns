package dns

import (
	"io"
	"text/scanner"
)

// ParseZone reads a RFC 1035 zone from r. It returns each parsed RR on the
// channel cr. The channel cr is closed by ParseZone when the end of r is reached.
func ParseKey(r io.Reader) (map[string]string, error) {
	var s scanner.Scanner
	m := make(map[string]string)
	c := make(chan Lex)
	k := ""
	s.Init(r)
	s.Mode = 0
	s.Whitespace = 0
	// Start the lexer
	go klexer(s, c)
	for l := range c {
		// It should alternate
		switch l.value {
		case _KEY:
			k = l.token
		case _VALUE:
			m[k] = l.token
		}
	}
	return m, nil
}

// klexer scans the sourcefile and returns tokens on the channel c.
func klexer(s scanner.Scanner, c chan Lex) {
	var l Lex
	str := "" // Hold the current read text
	commt := false
	key := true
	tok := s.Scan()
	defer close(c)
	for tok != scanner.EOF {
		l.column = s.Position.Column
		l.line = s.Position.Line
		switch x := s.TokenText(); x {
		case ":":
			if commt {
				break
			}
			if key {
				l.value = _KEY
				c <- l
				key = false
			} else {
				l.value = _VALUE
			}
		case ";":
			commt = true
		case "\n":
			if commt {
				// Reset a comment
				commt = false
			}
			c <- l
			str = ""
			commt = false
			key = true
		default:
			if commt {
				break
			}
			str += x
		}
		tok = s.Scan()
	}
}
