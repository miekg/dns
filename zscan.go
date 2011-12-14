package dns

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/scanner"
)

// Tokinize a RFC 1035 zone file. The tokenizer will normalize it:
// * Add ownernames;
// * Suppress sequences of spaces;
// * Make each RR fit on one line (NEWLINE is send as last)
// * Handle comments: ;
const (
	_STRING = iota
	_BLANK
	_NEWLINE
	_RRTYPE
	_OWNER
	_CLASS
)

const (
	_EXPECT_OWNER           = iota // Ownername
	_EXPECT_OWNER_BL               // Whitespace after the ownername
	_EXPECT_ANY                    // Expect rrtype, ttl or class
	_EXPECT_ANY_NO_CLASS           // Expect rrtype or ttl
	_EXPECT_ANY_NO_CLASS_BL        // The Whitespace after _EXPECT_ANY_NO_CLASS
	_EXPECT_ANY_NOTTL              // Expect rrtype or class
	_EXPECT_ANY_NOTTL_BL           // Whitespace after _EXPECT_ANY_NOTTL
	_EXPECT_RRTYPE                 // Expect rrtype
	_EXPECT_RRTYPE_BL              // Whitespace BEFORE rrype
	_EXPECT_RDATA                  // The first element of the rdata
	_EXPECT_RDATA_BL               // Whitespace BEFORE rdata starts
)

type Lex struct {
	token  string
	value  int
	line   int
	column int
}

// ParseZone reads a RFC 1035 zone from r. It returns each parsed RR on the
// channel cr. The channel cr is closed by ParseZone when the end of r is
// reached.
func ParseZone(r io.Reader, cr chan RR) {
        defer close(cr)
	var s scanner.Scanner
	c := make(chan Lex)
	s.Init(r)
	s.Mode = 0
	s.Whitespace = 0
        // Start the lexer
	go lexer(s, c)
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
		switch st {
		case _EXPECT_OWNER:
			switch l.value {
			case _NEWLINE: // Empty line
				st = _EXPECT_OWNER
			case _OWNER:
				h.Name = l.token
				st = _EXPECT_OWNER_BL
			default:
				println("Error at the start")
				st = _EXPECT_OWNER
			}
		case _EXPECT_OWNER_BL:
			if l.value != _BLANK {
				println("No blank after owner error")
			}
			st = _EXPECT_ANY
		case _EXPECT_ANY:
			switch l.value {
			case _RRTYPE:
				h.Rrtype, ok = Str_rr[strings.ToUpper(l.token)]
				if !ok {
					println("Unknown RR type")
				}
				h.Ttl = DefaultTtl
				st = _EXPECT_RDATA_BL
			case _CLASS:
				h.Class, ok = Str_class[strings.ToUpper(l.token)]
				if !ok {
					println("Unknown Class")
				}
				st = _EXPECT_ANY_NO_CLASS_BL
			case _STRING: // TTL is this case
				ttl, ok := strconv.Atoi(l.token)
				if ok != nil {
					println("Not a TTL")
				} else {
					h.Ttl = uint32(ttl)
				}
				st = _EXPECT_ANY_NOTTL_BL
			default:
				println("Error not expected")
			}
		case _EXPECT_ANY_NO_CLASS_BL:
			if l.value != _BLANK {
				println("No blank before NO_CLASS error")
			}
			st = _EXPECT_ANY_NO_CLASS
		case _EXPECT_ANY_NOTTL_BL:
			if l.value != _BLANK {
				println("No blank before NOTTL error")
			}
			st = _EXPECT_ANY_NOTTL
		case _EXPECT_ANY_NOTTL:
			switch l.value {
			case _CLASS:
				h.Class, ok = Str_class[strings.ToUpper(l.token)]
				if !ok {
					println("Unknown Class")
				}
				st = _EXPECT_RRTYPE_BL
			case _RRTYPE:
				h.Rrtype, ok = Str_rr[strings.ToUpper(l.token)]
				if !ok {
					println("Unknown RR type")
				}
				st = _EXPECT_RDATA_BL
			}
		case _EXPECT_ANY_NO_CLASS:
			switch l.value {
			case _STRING: // TTL
				ttl, ok := strconv.Atoi(l.token)
				if ok != nil {
					println("Not a TTL")
				} else {
					h.Ttl = uint32(ttl)
				}
				st = _EXPECT_RDATA_BL
			case _RRTYPE:
				h.Rrtype, ok = Str_rr[strings.ToUpper(l.token)]
				if !ok {
					println("Unknown RR type")
				}
				st = _EXPECT_RDATA_BL
			default:
				println("Error not TTL nor _RRTYPE seen")
			}
		case _EXPECT_RRTYPE_BL:
			if l.value != _BLANK {
				println("No blank after error")
			}
			st = _EXPECT_RRTYPE
		case _EXPECT_RRTYPE:
			if l.value != _RRTYPE {
				println("Error, not an rrtype")
			}
			h.Rrtype, ok = Str_rr[strings.ToUpper(l.token)]
			if !ok {
				println("Unknown RR type")
			}
			st = _EXPECT_RDATA_BL
		case _EXPECT_RDATA_BL:
			if l.value != _BLANK {
				println("No blank after error")
			}
			st = _EXPECT_RDATA
		case _EXPECT_RDATA:
			fmt.Printf("%v\n", h)
			// Remaining items until newline are rdata
			// reset
			fmt.Printf("%v", l)
			for rdata := range c {
				fmt.Printf("%v", rdata)
				if rdata.value == _NEWLINE {
					break
				}
			}
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

// lexer scans the sourcefile and returns tokens on the channel c.
func lexer(s scanner.Scanner, c chan Lex) {
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
			str += "\""
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
				fmt.Printf("Error\n")
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
	// Hmm
	//	fmt.Printf("XX %s XXX", str)
}
