package dns

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Only used when debugging the parser itself.
var _DEBUG = false

// Complete unsure about the correctness of this value?
// Large blobs of base64 code might get longer than this....
const maxTok = 2048

// Tokinize a RFC 1035 zone file. The tokenizer will normalize it:
// * Add ownernames if they are left blank;
// * Suppress sequences of spaces;
// * Make each RR fit on one line (NEWLINE is send as last)
// * Handle comments: ;
// * Handle braces.
const (
	// Zonefile
	_EOF = iota
	_STRING
	_BLANK
	_QUOTE
	_NEWLINE
	_RRTYPE
	_OWNER
	_CLASS
	_DIRORIGIN   // $ORIGIN
	_DIRTTL      // $TTL
	_DIRINCLUDE  // $INCLUDE
	_DIRGENERATE // $GENERATE

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
	_EXPECT_DIRGENERATE    // Directive $GENERATE
	_EXPECT_DIRGENERATE_BL // Space after directive $GENERATE
)

// ParseError is a parsing error. It contains the parse error and the location in the io.Reader
// where the error occured.
type ParseError struct {
	file string
	err  string
	lex  lex
}

func (e *ParseError) Error() (s string) {
	if e.file != "" {
		s = e.file + ": "
	}
	s += "dns: " + e.err + ": " + strconv.QuoteToASCII(e.lex.token) + " at line: " +
		strconv.Itoa(e.lex.line) + ":" + strconv.Itoa(e.lex.column)
	return
}

type lex struct {
	token  string // Text of the token
	err    bool   // When true, token text has lexer error 
	value  uint8  // Value: _STRING, _BLANK, etc.
	line   int    // Line in the file
	column int    // Column in the file
	torc   uint16 // Type or class as parsed in the lexer, we only need to look this up in the grammar
}

// Tokens are returned when a zone file is parsed.
type Token struct {
	RR                // the scanned resource record when error is not nil
	Error *ParseError // when an error occured, this has the error specifics
}

// NewRR reads the RR contained in the string s. Only the first RR is returned.
// The class defaults to IN and TTL defaults to 3600. The full zone file
// syntax like $TTL, $ORIGIN, etc. is supported.
func NewRR(s string) (RR, error) {
	if s[len(s)-1] != '\n' { // We need a closing newline
		return ReadRR(strings.NewReader(s+"\n"), "")
	}
	return ReadRR(strings.NewReader(s), "")
}

// ReadRR reads the RR contained in q. Only the first RR is returned.
// The class defaults to IN and TTL defaults to 3600.
func ReadRR(q io.Reader, filename string) (RR, error) {
	r := <-parseZoneHelper(q, ".", filename, 1)
	if r.Error != nil {
		return nil, r.Error
	}
	return r.RR, nil
}

// ParseZone reads a RFC 1035 style one from r. It returns Tokens on the 
// returned channel, which consist out the parsed RR or an error. 
// If there is an error the RR is nil. The string file is only used
// in error reporting. The string origin is used as the initial origin, as
// if the file would start with: $ORIGIN origin  .
// The directives $INCLUDE, $ORIGIN, $TTL and $GENERATE are supported.
// The channel t is closed by ParseZone when the end of r is reached.
//
// Basic usage pattern when reading from a string (z) containing the 
// zone data:
//
//	for x := range dns.ParseZone(strings.NewReader(z), "", "") {
//		if x.Error != nil {
//			// Do something with x.RR
//		}
//	}      
func ParseZone(r io.Reader, origin, file string) chan Token {
	return parseZoneHelper(r, origin, file, 10000)
}

func parseZoneHelper(r io.Reader, origin, file string, chansize int) chan Token {
	t := make(chan Token, chansize)
	go parseZone(r, origin, file, t, 0)
	return t

}

func parseZone(r io.Reader, origin, f string, t chan Token, include int) {
	defer func() {
		if include == 0 {
			close(t)
		}
	}()
	s := scanInit(r)
	c := make(chan lex, 1000)
	// Start the lexer
	go zlexer(s, c)
	// 6 possible beginnings of a line, _ is a space
	// 0. _RRTYPE                              -> all omitted until the rrtype
	// 1. _OWNER _ _RRTYPE                     -> class/ttl omitted
	// 2. _OWNER _ _STRING _ _RRTYPE           -> class omitted
	// 3. _OWNER _ _STRING _ _CLASS  _ _RRTYPE -> ttl/class
	// 4. _OWNER _ _CLASS  _ _RRTYPE           -> ttl omitted
	// 5. _OWNER _ _CLASS  _ _STRING _ _RRTYPE -> class/ttl (reversed)
	// After detecting these, we know the _RRTYPE so we can jump to functions
	// handling the rdata for each of these types.

	if origin == "" {
		origin = "."
	}
	if _, _, ok := IsDomainName(origin); !ok {
		t <- Token{Error: &ParseError{f, "bad initial origin name", lex{}}}
		return
	}
	origin = Fqdn(origin)

	st := _EXPECT_OWNER_DIR // initial state
	var h RR_Header
	var defttl uint32 = defaultTtl
	var prevName string
	for l := range c {
		if _DEBUG {
			fmt.Printf("[%v]\n", l)
		}
		// Lexer spotted an error already
		if l.err == true {
			t <- Token{Error: &ParseError{f, l.token, l}}
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
				if l.token[0] == '@' {
					h.Name = origin
					prevName = h.Name
					st = _EXPECT_OWNER_BL
					break
				}
				_, ld, ok := IsDomainName(l.token)
				if !ok {
					t <- Token{Error: &ParseError{f, "bad owner name", l}}
					return
				}
				if h.Name[ld-1] != '.' {
					h.Name = appendOrigin(h.Name, origin)
				}
				prevName = h.Name
				st = _EXPECT_OWNER_BL
			case _DIRTTL:
				st = _EXPECT_DIRTTL_BL
			case _DIRORIGIN:
				st = _EXPECT_DIRORIGIN_BL
			case _DIRINCLUDE:
				st = _EXPECT_DIRINCLUDE_BL
			case _DIRGENERATE:
				st = _EXPECT_DIRGENERATE_BL
			case _RRTYPE: // Everthing has been omitted, this is the first thing on the line
				h.Name = prevName
				h.Rrtype = l.torc
				st = _EXPECT_RDATA
			case _CLASS: // First thing on the line is the class
				h.Name = prevName
				h.Class = l.torc
				st = _EXPECT_ANY_NOCLASS_BL
			case _BLANK:
				// Discard, can happen when there is nothing on the
				// line except the RR type
			case _STRING: // First thing on the is the ttl
				if ttl, ok := stringToTtl(l.token); !ok {
					t <- Token{Error: &ParseError{f, "not a TTL", l}}
					return
				} else {
					h.Ttl = ttl
					defttl = ttl
				}
				st = _EXPECT_ANY_NOTTL_BL

			default:
				t <- Token{Error: &ParseError{f, "syntax error at beginning", l}}
				return
			}
		case _EXPECT_DIRINCLUDE_BL:
			if l.value != _BLANK {
				t <- Token{Error: &ParseError{f, "no blank after $INCLUDE-directive", l}}
				return
			}
			st = _EXPECT_DIRINCLUDE
		case _EXPECT_DIRINCLUDE:
			if l.value != _STRING {
				t <- Token{Error: &ParseError{f, "expecting $INCLUDE value, not this...", l}}
				return
			}
			if e := slurpRemainder(c, f); e != nil {
				t <- Token{Error: e}
			}
			// Start with the new file
			r1, e1 := os.Open(l.token)
			if e1 != nil {
				t <- Token{Error: &ParseError{f, "failed to open `" + l.token + "'", l}}
				return
			}
			if include+1 > 7 {
				t <- Token{Error: &ParseError{f, "too deeply nested $INCLUDE", l}}
				return
			}
			parseZone(r1, l.token, origin, t, include+1)
			st = _EXPECT_OWNER_DIR
		case _EXPECT_DIRTTL_BL:
			if l.value != _BLANK {
				t <- Token{Error: &ParseError{f, "no blank after $TTL-directive", l}}
				return
			}
			st = _EXPECT_DIRTTL
		case _EXPECT_DIRTTL:
			if l.value != _STRING {
				t <- Token{Error: &ParseError{f, "expecting $TTL value, not this...", l}}
				return
			}
			if e := slurpRemainder(c, f); e != nil {
				t <- Token{Error: e}
				return
			}
			if ttl, ok := stringToTtl(l.token); !ok {
				t <- Token{Error: &ParseError{f, "expecting $TTL value, not this...", l}}
				return
			} else {
				defttl = ttl
			}
			st = _EXPECT_OWNER_DIR
		case _EXPECT_DIRORIGIN_BL:
			if l.value != _BLANK {
				t <- Token{Error: &ParseError{f, "no blank after $ORIGIN-directive", l}}
				return
			}
			st = _EXPECT_DIRORIGIN
		case _EXPECT_DIRORIGIN:
			if l.value != _STRING {
				t <- Token{Error: &ParseError{f, "expecting $ORIGIN value, not this...", l}}
				return
			}
			if e := slurpRemainder(c, f); e != nil {
				t <- Token{Error: e}
			}
			if !IsFqdn(l.token) {
				if origin != "." { // Prevent .. endings
					origin = l.token + "." + origin
				} else {
					origin = l.token + origin
				}
			} else {
				origin = l.token
			}
			st = _EXPECT_OWNER_DIR
		case _EXPECT_DIRGENERATE_BL:
			if l.value != _BLANK {
				t <- Token{Error: &ParseError{f, "no blank after $GENERATE-directive", l}}
				return
			}
			st = _EXPECT_DIRGENERATE
		case _EXPECT_DIRGENERATE:
			if l.value != _STRING {
				t <- Token{Error: &ParseError{f, "expecting $GENERATE value, not this...", l}}
				return
			}
			if e := generate(l, c, t, origin); e != "" {
				t <- Token{Error: &ParseError{f, e, l}}
				return
			}
			st = _EXPECT_OWNER_DIR
		case _EXPECT_OWNER_BL:
			if l.value != _BLANK {
				t <- Token{Error: &ParseError{f, "no blank after owner", l}}
				return
			}
			st = _EXPECT_ANY
		case _EXPECT_ANY:
			switch l.value {
			case _RRTYPE:
				h.Rrtype = l.torc
				st = _EXPECT_RDATA
			case _CLASS:
				h.Class = l.torc
				st = _EXPECT_ANY_NOCLASS_BL
			case _STRING: // TTL is this case
				if ttl, ok := stringToTtl(l.token); !ok {
					t <- Token{Error: &ParseError{f, "not a TTL", l}}
					return
				} else {
					h.Ttl = ttl
					defttl = ttl
				}
				st = _EXPECT_ANY_NOTTL_BL
			default:
				t <- Token{Error: &ParseError{f, "expecting RR type, TTL or class, not this...", l}}
				return
			}
		case _EXPECT_ANY_NOCLASS_BL:
			if l.value != _BLANK {
				t <- Token{Error: &ParseError{f, "no blank before class", l}}
				return
			}
			st = _EXPECT_ANY_NOCLASS
		case _EXPECT_ANY_NOTTL_BL:
			if l.value != _BLANK {
				t <- Token{Error: &ParseError{f, "no blank before TTL", l}}
				return
			}
			st = _EXPECT_ANY_NOTTL
		case _EXPECT_ANY_NOTTL:
			switch l.value {
			case _CLASS:
				h.Class = l.torc
				st = _EXPECT_RRTYPE_BL
			case _RRTYPE:
				h.Rrtype = l.torc
				st = _EXPECT_RDATA
			default:
				t <- Token{Error: &ParseError{f, "expecting RR type or class, not this...", l}}
				return
			}
		case _EXPECT_ANY_NOCLASS:
			switch l.value {
			case _STRING: // TTL
				if ttl, ok := stringToTtl(l.token); !ok {
					t <- Token{Error: &ParseError{f, "not a TTL", l}}
					return
				} else {
					h.Ttl = ttl
					defttl = ttl
				}
				st = _EXPECT_RRTYPE_BL
			case _RRTYPE:
				h.Rrtype = l.torc
				st = _EXPECT_RDATA
			default:
				t <- Token{Error: &ParseError{f, "expecting RR type or TTL, not this...", l}}
				return
			}
		case _EXPECT_RRTYPE_BL:
			if l.value != _BLANK {
				t <- Token{Error: &ParseError{f, "no blank before RR type", l}}
				return
			}
			st = _EXPECT_RRTYPE
		case _EXPECT_RRTYPE:
			if l.value != _RRTYPE {
				t <- Token{Error: &ParseError{f, "unknown RR type", l}}
				return
			}
			h.Rrtype = l.torc
			st = _EXPECT_RDATA
		case _EXPECT_RDATA:
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
	// If we get here, we and the h.Rrtype is still zero, we haven't parsed anything, this
	// is not an error, because an empty zone file is still a zone file.
}

// zlexer scans the sourcefile and returns tokens on the channel c.
func zlexer(s *scan, c chan lex) {
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
	x, err := s.tokenText()
	defer close(c)
	for err == nil {
		l.column = s.position.Column
		l.line = s.position.Line
		if stri > maxTok {
			l.token = "tok length insufficient for parsing"
			l.err = true
			c <- l
			return
		}

		switch x {
		case ' ', '\t':
			if quote {
				// Inside quotes this is legal
				str[stri] = x
				stri++
				break
			}
			escape = false
			if commt {
				break
			}
			if stri == 0 {
				// Space directly as the beginnin, handled in the grammar
			} else if owner {
				// If we have a string and its the first, make it an owner
				l.value = _OWNER
				l.token = string(str[:stri])
				// escape $... start with a \ not a $, so this will work
				switch l.token {
				case "$TTL":
					l.value = _DIRTTL
				case "$ORIGIN":
					l.value = _DIRORIGIN
				case "$INCLUDE":
					l.value = _DIRINCLUDE
				case "$GENERATE":
					l.value = _DIRGENERATE
				}
				c <- l
			} else {
				l.value = _STRING
				l.token = string(str[:stri])

				if !rrtype {
					if t, ok := Str_rr[strings.ToUpper(l.token)]; ok {
						l.value = _RRTYPE
						l.torc = t
						rrtype = true
					} else {
						if strings.HasPrefix(l.token, "TYPE") {
							if t, ok := typeToInt(l.token); !ok {
								l.token = "unknown RR type"
								l.err = true
								c <- l
								return
							} else {
								l.value = _RRTYPE
								l.torc = t
							}
						}
					}
					if t, ok := Str_class[strings.ToUpper(l.token)]; ok {
						l.value = _CLASS
						l.torc = t
					} else {
						if strings.HasPrefix(l.token, "CLASS") {
							if t, ok := classToInt(l.token); !ok {
								l.token = "unknown class"
								l.err = true
								c <- l
								return
							} else {
								l.value = _CLASS
								l.torc = t
							}
						}
					}
				}
				c <- l
			}
			stri = 0
			// I reverse space stuff here
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
				str[stri] = x
				stri++
				break
			}
			if escape {
				escape = false
				str[stri] = x
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
		case '\r':
			// discard
			// this means it can also not be used as rdata
		case '\n':
			// Escaped newline
			if quote {
				str[stri] = x
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
					owner = true
					l.value = _NEWLINE
					l.token = "\n"
					c <- l
				}
				break
			}

			if brace == 0 {
				// If there is previous text, we should output it here
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
				l.value = _NEWLINE
				l.token = "\n"
				c <- l
				stri = 0
				commt = false
				rrtype = false
				owner = true
			}
		case '\\':
			// quote?
			if commt {
				break
			}
			if escape {
				str[stri] = x
				stri++
				escape = false
				break
			}
			str[stri] = x
			stri++
			escape = true
		case '"':
			if commt {
				break
			}
			if escape {
				str[stri] = x
				stri++
				escape = false
				break
			}
			space = false
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
		case '(', ')':
			if quote {
				str[stri] = x
				stri++
				break
			}
			if commt {
				break
			}
			if escape {
				str[stri] = x
				stri++
				escape = false
				break
			}
			switch x {
			case ')':
				brace--
				if brace < 0 {
					l.token = "extra closing brace"
					l.err = true
					c <- l
					return
				}
			case '(':
				brace++
			}
		default:
			if commt {
				break
			}
			escape = false
			str[stri] = x
			stri++
			space = false
		}
		x, err = s.tokenText()
	}
	// Hmm.
	if stri > 0 {
		// Send remainder
		l.token = string(str[:stri])
		l.value = _STRING
		c <- l
	}
}

// Extract the class number from CLASSxx
func classToInt(token string) (uint16, bool) {
	class, ok := strconv.Atoi(token[5:])
	if ok != nil {
		return 0, false
	}
	return uint16(class), true
}

// Extract the rr number from TYPExxx 
func typeToInt(token string) (uint16, bool) {
	typ, ok := strconv.Atoi(token[4:])
	if ok != nil {
		return 0, false
	}
	return uint16(typ), true
}

// Parse things like 2w, 2m, etc, Return the time in seconds.
func stringToTtl(token string) (uint32, bool) {
	s := uint32(0)
	i := uint32(0)
	for _, c := range token {
		switch c {
		case 's', 'S':
			s += i
			i = 0
		case 'm', 'M':
			s += i * 60
			i = 0
		case 'h', 'H':
			s += i * 60 * 60
			i = 0
		case 'd', 'D':
			s += i * 60 * 60 * 24
			i = 0
		case 'w', 'W':
			s += i * 60 * 60 * 24 * 7
			i = 0
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			i *= 10
			i += uint32(c) - '0'
		default:
			return 0, false
		}
	}
	return s + i, true
}

// Parse LOC records' <digits>[.<digits>][mM] into a 
// mantissa exponent format. Token should contain the entire
// string (i.e. no spaces allowed)
func stringToCm(token string) (e, m uint8, ok bool) {
	if token[len(token)-1] == 'M' || token[len(token)-1] == 'm' {
		token = token[0 : len(token)-1]
	}
	s := strings.SplitN(token, ".", 2)
	var meters, cmeters, val int
	var err error
	switch len(s) {
	case 2:
		if cmeters, err = strconv.Atoi(s[1]); err != nil {
			return
		}
		fallthrough
	case 1:
		if meters, err = strconv.Atoi(s[0]); err != nil {
			return
		}
	case 0:
		// huh?
		return 0, 0, false
	}
	ok = true
	if meters > 0 {
		e = 2
		val = meters
	} else {
		e = 0
		val = cmeters
	}
	for val > 10 {
		e++
		val /= 10
	}
	if e > 9 {
		ok = false
	}
	m = uint8(val)
	return
}

func appendOrigin(name, origin string) string {
	if origin == "." {
		return name + origin
	}
	return name + "." + origin
}

// LOC record helper function                                                                        
func locCheckNorth(token string, latitude uint32) (uint32, bool) {
	switch token {
	case "n", "N":
		return _LOC_EQUATOR + latitude, true
	case "s", "S":
		return _LOC_EQUATOR - latitude, true
	}
	return latitude, false
}

// LOC record helper function                                                                        
func locCheckEast(token string, longitude uint32) (uint32, bool) {
	switch token {
	case "e", "E":
		return _LOC_EQUATOR + longitude, true
	case "w", "W":
		return _LOC_EQUATOR - longitude, true
	}
	return longitude, false
}

// "Eat" the rest of the "line"
func slurpRemainder(c chan lex, f string) *ParseError {
	l := <-c
	switch l.value {
	case _BLANK:
		l = <-c
		if l.value != _NEWLINE && l.value != _EOF {
			return &ParseError{f, "garbage after rdata", l}
		}
		// Ok
	case _NEWLINE:
		// Ok
	case _EOF:
		// Ok
	default:
		return &ParseError{f, "garbage after rdata", l}
	}
	return nil
}
