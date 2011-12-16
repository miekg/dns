package dns

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/scanner"
)

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
	_NEWLINE
	_RRTYPE
	_OWNER
	_CLASS

	// Privatekey file
	_VALUE
	_KEY

	_EXPECT_OWNER          // Ownername
	_EXPECT_OWNER_BL       // Whitespace after the ownername
	_EXPECT_ANY            // Expect rrtype, ttl or class
	_EXPECT_ANY_NOCLASS    // Expect rrtype or ttl
	_EXPECT_ANY_NOCLASS_BL // The Whitespace after _EXPECT_ANY_NOCLASS
	_EXPECT_ANY_NOTTL      // Expect rrtype or class
	_EXPECT_ANY_NOTTL_BL   // Whitespace after _EXPECT_ANY_NOTTL
	_EXPECT_RRTYPE         // Expect rrtype
	_EXPECT_RRTYPE_BL      // Whitespace BEFORE rrtype
	_EXPECT_RDATA          // The first element of the rdata
)

// Only used when debugging the parser itself.
var DEBUG = false

type ParseError struct {
	err string
	lex Lex
}

func (e *ParseError) Error() string {
	s := e.err + ": `" + e.lex.token + "' at line: " + strconv.Itoa(e.lex.line) +
		" and column: " + strconv.Itoa(e.lex.column)
	return s
}

type Lex struct {
	token  string // text of the token
	value  int    // value: _STRING, _BLANK, etc.
	line   int    // line in the file
	column int    // column in the fil
}

type Token struct {
	Rr  RR          // the scanned resource record
	Error *ParseError // when an error occured, this is the specifics
}

// NewRR parses the string s and returns the RR contained in there. If the string
// contains more than one RR, only the first is returned. If an error is detected
// that error error is returned. 
// If the class is not specified, the IN class is assumed. If the TTL is not
// specified DefaultTtl is assumed.
func NewRR(s string) (RR, error) {
	t := make(chan Token)
	if s[len(s)-1] != '\n' { // We need a closing newline
		go ParseZone(strings.NewReader(s+"\n"), t)
	} else {
		go ParseZone(strings.NewReader(s), t)
	}
	r := <-t
	if r.Error != nil {
		return nil, r.Error
	}
	return r.Rr, nil
}

// ParseZone reads a RFC 1035 zone from r. It returns each parsed RR or on error
// on the channel t. The channel t is closed by ParseZone when the end of r is reached.
// Basic usage pattern:
// go ParseZone
func ParseZone(r io.Reader, t chan Token) {
	defer close(t)
	var s scanner.Scanner
	c := make(chan Lex)
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
	st := _EXPECT_OWNER
	var h RR_Header
	var ok bool
	for l := range c {
		if DEBUG {
			fmt.Printf("[%v]\n", l)
		}
		switch st {
		case _EXPECT_OWNER:
			// Set the defaults here
			h.Ttl = DefaultTtl
			h.Class = ClassINET
			switch l.value {
			case _NEWLINE: // Empty line
				st = _EXPECT_OWNER
			case _OWNER:
				h.Name = l.token
				st = _EXPECT_OWNER_BL
			default:
				t <- Token{Error: &ParseError{"Error at the start", l}}
				return
				//st = _EXPECT_OWNER
			}
		case _EXPECT_OWNER_BL:
			if l.value != _BLANK {
				t <- Token{Error: &ParseError{"No blank after owner", l}}
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
					t <- Token{Error: &ParseError{"Unknown class", l}}
					return
				}
				st = _EXPECT_ANY_NOCLASS_BL
			case _STRING: // TTL is this case
				ttl, ok := strconv.Atoi(l.token)
				if ok != nil {
					t <- Token{Error: &ParseError{"Not a TTL", l}}
					return
				} else {
					h.Ttl = uint32(ttl)
				}
				st = _EXPECT_ANY_NOTTL_BL
			default:
				t <- Token{Error: &ParseError{"Expecting RR type, TTL or class, not this...", l}}
				return
			}
		case _EXPECT_ANY_NOCLASS_BL:
			if l.value != _BLANK {
				t <- Token{Error: &ParseError{"No blank before NOCLASS", l}}
				return
			}
			st = _EXPECT_ANY_NOCLASS
		case _EXPECT_ANY_NOTTL_BL:
			if l.value != _BLANK {
				t <- Token{Error: &ParseError{"No blank before NOTTL", l}}
				return
			}
			st = _EXPECT_ANY_NOTTL
		case _EXPECT_ANY_NOTTL:
			switch l.value {
			case _CLASS:
				h.Class, ok = Str_class[strings.ToUpper(l.token)]
				if !ok {
					t <- Token{Error: &ParseError{"Unknown class", l}}
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
				ttl, ok := strconv.Atoi(l.token)
				if ok != nil {
					t <- Token{Error: &ParseError{"Not a TTL", l}}
					return
				} else {
					h.Ttl = uint32(ttl)
				}
				st = _EXPECT_RRTYPE_BL
			case _RRTYPE:
				h.Rrtype, _ = Str_rr[strings.ToUpper(l.token)]
				st = _EXPECT_RDATA
			default:
				t <- Token{Error: &ParseError{"Expecting RR type or TTL, not this...", l}}
				return
			}
		case _EXPECT_RRTYPE_BL:
			if l.value != _BLANK {
				t <- Token{Error: &ParseError{"No blank after", l}}
				return
			}
			st = _EXPECT_RRTYPE
		case _EXPECT_RRTYPE:
			if l.value != _RRTYPE {
				t <- Token{Error: &ParseError{"Unknown RR type", l}}
				return
			}
			h.Rrtype, _ = Str_rr[strings.ToUpper(l.token)]
			st = _EXPECT_RDATA
		case _EXPECT_RDATA:
			// I could save my token here...? l
			r, e := setRR(h, c)
			if e != nil {
				t <- Token{Error: e}
				return
			}
			t <- Token{Rr: r}
			st = _EXPECT_OWNER
		}
	}
}

func (l Lex) String() string {
	switch l.value {
	case _STRING:
		return l.token
	case _BLANK:
		return " " //"_" // seems to work, make then invisible for now
	case _NEWLINE:
		return "|\n"
	case _RRTYPE:
		return "R:" + l.token
	case _OWNER:
		return "O:" + l.token
	case _CLASS:
		return "C:" + l.token
	}
	return ""
}

// zlexer scans the sourcefile and returns tokens on the channel c.
func zlexer(s scanner.Scanner, c chan Lex) {
	var l Lex
	str := "" // Hold the current read text
	quote := false
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
		switch x := s.TokenText(); x {
		case " ", "\t":
			if commt {
				break
			}
			if str == "" {
				//l.value = _BLANK
				//l.token = " "
			} else if owner {
				// If we have a string and its the first, make it an owner
				l.value = _OWNER
				l.token = str
				c <- l
			} else {
				l.value = _STRING
				l.token = str

				if !rrtype {
					if _, ok := Str_rr[strings.ToUpper(l.token)]; ok {
						l.value = _RRTYPE
						rrtype = true // We've seen one
					}
					if _, ok := Str_class[strings.ToUpper(l.token)]; ok {
						l.value = _CLASS
					}
				}
				c <- l
			}
			str = ""
			if !space && !commt {
				l.value = _BLANK
				l.token = " "
				c <- l
			}
			space = true
			owner = false
		case ";":
			if quote {
				// Inside quoted text we allow ;
				str += ";"
				break
			}
			commt = true
		case "\n":
			if commt {
				// Reset a comment
				commt = false
				rrtype = false
				str = ""
				break
			}
			if str != "" {
				l.value = _STRING
				l.token = str
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

			str = ""
			commt = false
			rrtype = false
			owner = true
		case "\"":
			if commt {
				break
			}
			// str += "\"" don't add quoted quotes
			quote = !quote
		case "(":
			if commt {
				break
			}
			brace++
		case ")":
			if commt {
				break
			}
			brace--
			if brace < 0 {
				fmt.Printf("%s\n", &ParseError{"Extra closing brace", l})
			}
		default:
			if commt {
				break
			}
			str += x
			space = false
		}
		tok = s.Scan()
	}
}
