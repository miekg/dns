package dns

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/scanner"
)

// Only used when debugging the parser itself.
var _DEBUG = false

// Complete unsure about the correctness of this value?
// Large blobs of base64 code might get longer than this....
const maxTok = 300

// Tokinize a RFC 1035 zone file. The tokenizer will normalize it:
// * Add ownernames if they are left blank;
// * Suppress sequences of spaces;
// * Make each RR fit on one line (NEWLINE is send as last)
// * Handle comments: ;
// * Handle braces.
const (
	// Zonefile
	_EOF = iota // Don't let it start with zero
	_STRING
	_BLANK
	_QUOTE
	_NEWLINE
	_RRTYPE
	_OWNER
	_CLASS
	_DIRORIGIN  // $ORIGIN
	_DIRTTL     // $TTL
	_DIRINCLUDE // $INCLUDE

	// Privatekey file
	_VALUE
	_KEY

	_EXPECT_OWNER_DIR      // Ownername
	_EXPECT_OWNER_BL       // Whitespace after the ownername
	_EXPECT_ANY            // Expect rrtype, ttl or class
	_EXPECT_ANY_NOCLASS    // Expect rrtype or ttl
	_EXPECT_ANY_NOCLASS_BL // The Whitespace after _EXPECT_ANY_NOCLASS
	_EXPECT_ANY_NOTTL      // Expect rrtype or class
	_EXPECT_ANY_NOTTL_BL   // Whitespace after _EXPECT_ANY_NOTTL
	_EXPECT_RRTYPE         // Expect rrtype
	_EXPECT_RRTYPE_BL      // Whitespace BEFORE rrtype
	_EXPECT_RDATA          // The first element of the rdata
	_EXPECT_DIRTTL_BL      // Space after directive $TTL
	_EXPECT_DIRTTL         // Directive $TTL
	_EXPECT_DIRORIGIN_BL   // Space after directive $ORIGIN
	_EXPECT_DIRORIGIN      // Directive $ORIGIN
	_EXPECT_DIRINCLUDE_BL  // Space after directive $INCLUDE
	_EXPECT_DIRINCLUDE     // Directive $INCLUDE
)

// ParseError contains the parse error and the location in the io.Reader
// where the error occured.
type ParseError struct {
	file string
	err  string
	lex  lex
}

func (e *ParseError) Error() (s string) {
	//	va := strconv.Itoa(e.lex.value)
	if e.file != "" {
		s = e.file + ": "
	}
	s += e.err + ": `" + e.lex.token + "' at line: " +
		strconv.Itoa(e.lex.line) + ":" + strconv.Itoa(e.lex.column)
	return
}

type lex struct {
	token  string // Text of the token
	err    string // Error text when the lexer detects it. Not used by the grammar
	value  int    // Value: _STRING, _BLANK, etc.
	line   int    // Line in the file
	column int    // Column in the fil
}

type Token struct {
	RR                // the scanned resource record
	Error *ParseError // when an error occured, this is the specifics
}

// NewRR reads the RR contained in the string s. Only the first RR is returned.
// The class defaults to IN and TTL defaults to DefaultTtl
func NewRR(s string) (RR, error) {
	if s[len(s)-1] != '\n' { // We need a closing newline
		return ReadRR(strings.NewReader(s+"\n"), "")
	}
	return ReadRR(strings.NewReader(s), "")
}

// Ioreader here, or filename which *we* open....???

// ReadRR reads the RR contained in q. Only the first RR is returned.
// The class defaults to IN and TTL defaults to DefaultTtl.
func ReadRR(q io.Reader, filename string) (RR, error) {
	r := <-ParseZone(q, filename)
	if r.Error != nil {
		return nil, r.Error
	}
	return r.RR, nil
}

// ParseZone reads a RFC 1035 zone from r. It returns each parsed RR or an error
// on the returned channel. The channel t is closed by ParseZone when the end of r is reached.
func ParseZone(r io.Reader, file string) chan Token {
	t := make(chan Token)
	go parseZone(r, file, t, 0)
	return t
}

func parseZone(r io.Reader, f string, t chan Token, include int) {
	defer func() {
		if include == 0 {
			close(t)
		}
	}()
	var s scanner.Scanner
	c := make(chan lex)
	s.Init(r)
	s.Mode = 0
	s.Whitespace = 0
	// Start the lexer
	go zlexer(s, c)
	// 5 possible beginnings of a line, _ is a space
	// 1. _OWNER _ _RRTYPE                     -> class/ttl omitted
	// 2. _OWNER _ _STRING _ _RRTYPE           -> class omitted
	// 3. _OWNER _ _STRING _ _CLASS  _ _RRTYPE -> ttl/class
	// 4. _OWNER _ _CLASS  _ _RRTYPE           -> ttl omitted
	// 5. _OWNER _ _CLASS  _ _STRING _ _RRTYPE -> class/ttl (reversed)
	// After detecting these, we know the _RRTYPE so we can jump to functions
	// handling the rdata for each of these types.
	st := _EXPECT_OWNER_DIR
	var h RR_Header
	var ok bool
	var defttl uint32 = DefaultTtl
	var origin string = "."
	for l := range c {
		if _DEBUG {
			fmt.Printf("[%v]\n", l)
		}
		// Lexer spotted an error already
		if l.err != "" {
			t <- Token{Error: &ParseError{f, l.err, l}}
			return

		}
		switch st {
		case _EXPECT_OWNER_DIR:
			// We can also expect a directive, like $TTL or $ORIGIN
			h.Ttl = defttl
			h.Class = ClassINET
			switch l.value {
			case _NEWLINE: // Empty line
				st = _EXPECT_OWNER_DIR
			case _OWNER:
				h.Name = l.token
				_, ld, ok := IsDomainName(l.token)
				if !ok {
					t <- Token{Error: &ParseError{f, "bad owner name", l}}
					return
				}
				if h.Name[ld-1] != '.' {
					h.Name += origin
				}
				st = _EXPECT_OWNER_BL
			case _DIRTTL:
				st = _EXPECT_DIRTTL_BL
			case _DIRORIGIN:
				st = _EXPECT_DIRORIGIN_BL
			case _DIRINCLUDE:
				st = _EXPECT_DIRINCLUDE_BL
			default:
				t <- Token{Error: &ParseError{f, "Error at the start", l}}
				return
			}
		case _EXPECT_DIRINCLUDE_BL:
			if l.value != _BLANK {
				t <- Token{Error: &ParseError{f, "No blank after $INCLUDE-directive", l}}
				return
			}
			st = _EXPECT_DIRINCLUDE
		case _EXPECT_DIRINCLUDE:
			if l.value != _STRING {
				t <- Token{Error: &ParseError{f, "Expecting $INCLUDE value, not this...", l}}
				return
			}
			// Start with the new file
			r1, e1 := os.Open(l.token)
			if e1 != nil {
				t <- Token{Error: &ParseError{f, "Failed to open `" + l.token + "'", l}}
				return
			}
			if include+1 > 7 {
				t <- Token{Error: &ParseError{f, "Too deeply nested $INCLUDE", l}}
				return
			}
			parseZone(r1, l.token, t, include+1)
			st = _EXPECT_OWNER_DIR
		case _EXPECT_DIRTTL_BL:
			if l.value != _BLANK {
				t <- Token{Error: &ParseError{f, "No blank after $TTL-directive", l}}
				return
			}
			st = _EXPECT_DIRTTL
		case _EXPECT_DIRTTL:
			if l.value != _STRING {
				t <- Token{Error: &ParseError{f, "Expecting $TTL value, not this...", l}}
				return
			}
			if ttl, ok := stringToTtl(l, f, t); !ok {
				return
			} else {
				defttl = ttl
			}
			st = _EXPECT_OWNER_DIR
		case _EXPECT_DIRORIGIN_BL:
			if l.value != _BLANK {
				t <- Token{Error: &ParseError{f, "No blank after $ORIGIN-directive", l}}
				return
			}
			st = _EXPECT_DIRORIGIN
		case _EXPECT_DIRORIGIN:
			if l.value != _STRING {
				t <- Token{Error: &ParseError{f, "Expecting $ORIGIN value, not this...", l}}
				return
			}
			if !IsFqdn(l.token) {
				origin = l.token + "." + origin // Append old origin if the new one isn't a fqdn
			} else {
				origin = "." + l.token
			}
			st = _EXPECT_OWNER_DIR
		case _EXPECT_OWNER_BL:
			if l.value != _BLANK {
				t <- Token{Error: &ParseError{f, "No blank after owner", l}}
				return
			}
			st = _EXPECT_ANY
		case _EXPECT_ANY:
			switch l.value {
			case _RRTYPE:
				h.Rrtype, _ = Str_rr[strings.ToUpper(l.token)]
				st = _EXPECT_RDATA
			case _CLASS:
				h.Class, ok = Str_class[strings.ToUpper(l.token)]
				if !ok {
					t <- Token{Error: &ParseError{f, "Unknown class", l}}
					return
				}
				st = _EXPECT_ANY_NOCLASS_BL
			case _STRING: // TTL is this case
				if ttl, ok := stringToTtl(l, f, t); !ok {
					return
				} else {
					h.Ttl = ttl
				}
				st = _EXPECT_ANY_NOTTL_BL
			default:
				t <- Token{Error: &ParseError{f, "Expecting RR type, TTL or class, not this...", l}}
				return
			}
		case _EXPECT_ANY_NOCLASS_BL:
			if l.value != _BLANK {
				t <- Token{Error: &ParseError{f, "No blank before NOCLASS", l}}
				return
			}
			st = _EXPECT_ANY_NOCLASS
		case _EXPECT_ANY_NOTTL_BL:
			if l.value != _BLANK {
				t <- Token{Error: &ParseError{f, "No blank before NOTTL", l}}
				return
			}
			st = _EXPECT_ANY_NOTTL
		case _EXPECT_ANY_NOTTL:
			switch l.value {
			case _CLASS:
				h.Class, ok = Str_class[strings.ToUpper(l.token)]
				if !ok {
					t <- Token{Error: &ParseError{f, "Unknown class", l}}
					return
				}
				st = _EXPECT_RRTYPE_BL
			case _RRTYPE:
				h.Rrtype, _ = Str_rr[strings.ToUpper(l.token)]
				st = _EXPECT_RDATA
			}
		case _EXPECT_ANY_NOCLASS:
			switch l.value {
			case _STRING: // TTL
				if ttl, ok := stringToTtl(l, f, t); !ok {
					return
				} else {
					h.Ttl = ttl
				}
				st = _EXPECT_RRTYPE_BL
			case _RRTYPE:
				h.Rrtype, _ = Str_rr[strings.ToUpper(l.token)]
				st = _EXPECT_RDATA
			default:
				t <- Token{Error: &ParseError{f, "Expecting RR type or TTL, not this...", l}}
				return
			}
		case _EXPECT_RRTYPE_BL:
			if l.value != _BLANK {
				t <- Token{Error: &ParseError{f, "No blank after", l}}
				return
			}
			st = _EXPECT_RRTYPE
		case _EXPECT_RRTYPE:
			if l.value != _RRTYPE {
				t <- Token{Error: &ParseError{f, "Unknown RR type", l}}
				return
			}
			h.Rrtype, _ = Str_rr[strings.ToUpper(l.token)]
			st = _EXPECT_RDATA
		case _EXPECT_RDATA:
			// I could save my token here...? l
			r, e := setRR(h, c, origin, f)
			if e != nil {
				// If e.lex is nil than we have encounter a unknown RR type
				// in that case we substitute our current lex token
				if e.lex.token == "" && e.lex.value == 0 {
					e.lex = l // Uh, dirty
				}
				t <- Token{Error: e}
				return
			}
			t <- Token{RR: r}
			st = _EXPECT_OWNER_DIR
		}
	}
}

func (l lex) String() string {
	switch l.value {
	case _STRING:
		return "S:" + l.token + "$"
	case _BLANK:
		return "_"
	case _QUOTE:
		return "\""
	case _NEWLINE:
		return "|\n"
	case _RRTYPE:
		return "R:" + l.token + "$"
	case _OWNER:
		return "O:" + l.token + "$"
	case _CLASS:
		return "C:" + l.token + "$"
	case _DIRTTL:
		return "T:" + l.token + "$"
	}
	return ""
}

// zlexer scans the sourcefile and returns tokens on the channel c.
func zlexer(s scanner.Scanner, c chan lex) {
	var l lex
	str := make([]byte, maxTok) // Should be enough for any token
	stri := 0                   // Offset in str (0 means empty)
	quote := false
	escape := false
	space := false
	commt := false
	rrtype := false
	owner := true
	brace := 0
	tok := s.Scan()
	defer close(c)
	for tok != scanner.EOF {
		l.column = s.Position.Column
		l.line = s.Position.Line
		if stri > maxTok {
			l.err = "tok length insufficient for parsing"
			c <- l
			return
		}
		// Each token we get is one byte, so we switch on that x[0]. This
		// avoids a len(x) that Go otherwise will perform when comparing strings.
		switch x := s.TokenText(); x[0] {
		case ' ', '\t':
			if quote {
				// Inside quotes this is legal
				str[stri] = byte(x[0])
				stri++
				break
			}
			escape = false
			if commt {
				break
			}
			if stri == 0 {
				//l.value = _BLANK
				//l.token = " "
			} else if owner {
				// If we have a string and its the first, make it an owner
				l.value = _OWNER
				l.token = string(str[:stri])
				// escape $... start with a \ not a $, so this will work
				switch string(str[:stri]) {
				case "$TTL":
					l.value = _DIRTTL
				case "$ORIGIN":
					l.value = _DIRORIGIN
				case "$INCLUDE":
					l.value = _DIRINCLUDE
				}
				c <- l
			} else {
				l.value = _STRING
				l.token = string(str[:stri])

				if !rrtype {
					if _, ok := Str_rr[strings.ToUpper(l.token)]; ok {
						l.value = _RRTYPE
						rrtype = true
					}
					if _, ok := Str_class[strings.ToUpper(l.token)]; ok {
						l.value = _CLASS
					}
				}
				c <- l
			}
			stri = 0
			if !space && !commt {
				l.value = _BLANK
				l.token = " "
				c <- l
			}
			owner = false
			space = true
		case ';':
			if quote {
				// Inside quotes this is legal
				str[stri] = byte(x[0])
				stri++
				break
			}
			if escape {
				escape = false
				str[stri] = byte(x[0])
				stri++
				break
			}
			if stri > 0 {
				l.value = _STRING
                                l.token = string(str[:stri])
				c <- l
                                stri = 0
			}
			commt = true
		case '\n':
			// Hmmm, escape newline
			if quote {
				str[stri] = byte(x[0])
				stri++
				break
			}

			// inside quotes this is legal
			escape = false
			if commt {
				// Reset a comment
				commt = false
				rrtype = false
				stri = 0
				// If not in a brace this ends the comment AND the RR
				if brace == 0 {
					owner = true
					l.value = _NEWLINE
					l.token = "\n"
					c <- l
				}
				break
			}
			if stri != 0 {
				l.value = _STRING
				l.token = string(str[:stri])
				if !rrtype {
					if _, ok := Str_rr[strings.ToUpper(l.token)]; ok {
						l.value = _RRTYPE
						rrtype = true
					}
				}
				c <- l
			}
			if brace > 0 {
				l.value = _BLANK
				l.token = " "
				if !space {
					c <- l
				}
			} else {
				l.value = _NEWLINE
				l.token = "\n"
				c <- l
			}
			if l.value == _BLANK {
				space = true
			}

			stri = 0
			commt = false
			rrtype = false
			owner = true
		case '\\':
			// quote?
			if commt {
				break
			}
			if escape {
				str[stri] = byte(x[0])
				stri++
				escape = false
				break
			}
			str[stri] = byte(x[0])
			stri++
			escape = true
		case '"':
			if commt {
				break
			}
			if escape {
				str[stri] = byte(x[0])
				stri++
				escape = false
				break
			}
			// send previous gathered text and the quote
			if stri != 0 {
				l.value = _STRING
				l.token = string(str[:stri])
				c <- l
				stri = 0
			}
			l.value = _QUOTE
			l.token = "\""
			c <- l
			quote = !quote
		case '(':
			if quote {
				str[stri] = byte(x[0])
				stri++
				break
			}
			if commt {
				break
			}
			if escape {
				str[stri] = byte(x[0])
				stri++
				escape = false
				break
			}
			brace++
		case ')':
			if quote {
				str[stri] = byte(x[0])
				stri++
				break
			}
			if commt {
				break
			}
			if escape {
				str[stri] = byte(x[0])
				stri++
				escape = false
				break
			}
			brace--
			if brace < 0 {
				l.err = "extra closing brace"
				c <- l
				return
			}
		default:
			if commt {
				break
			}
			escape = false
			str[stri] = byte(x[0])
			stri++
			space = false
		}
		tok = s.Scan()
	}
	// Hmm.
	if stri > 0 {
		// Send remainder
		l.token = string(str[:stri])
		l.value = _STRING
		c <- l
	}
}

func stringToTtl(l lex, f string, t chan Token) (uint32, bool) {
	if ttl, ok := strconv.Atoi(l.token); ok != nil {
		t <- Token{Error: &ParseError{f, "Not a TTL", l}}
		return 0, false
	} else {
		return uint32(ttl), true
	}
	panic("not reached")
}
