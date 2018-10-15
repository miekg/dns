package dns

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Parse the $GENERATE statement as used in BIND9 zones.
// See http://www.zytrax.com/books/dns/ch8/generate.html for instance.
// We are called after '$GENERATE '. After which we expect:
// * the range (12-24/2)
// * lhs (ownername)
// * [[ttl][class]]
// * type
// * rhs (rdata)
// But we are lazy here, only the range is parsed *all* occurrences
// of $ after that are interpreted.
// Any error are returned as a string value, the empty string signals
// "no error".
func (zp *ZoneParser) generate(l lex) string {
	origL := l
	step := 1
	if i := strings.IndexAny(l.token, "/"); i != -1 {
		if i+1 == len(l.token) {
			return "bad step in $GENERATE range"
		}
		if s, err := strconv.Atoi(l.token[i+1:]); err == nil {
			if s < 0 {
				return "bad step in $GENERATE range"
			}
			step = s
		} else {
			return "bad step in $GENERATE range"
		}
		l.token = l.token[:i]
	}
	sx := strings.SplitN(l.token, "-", 2)
	if len(sx) != 2 {
		return "bad start-stop in $GENERATE range"
	}
	start, err := strconv.Atoi(sx[0])
	if err != nil {
		return "bad start in $GENERATE range"
	}
	end, err := strconv.Atoi(sx[1])
	if err != nil {
		return "bad stop in $GENERATE range"
	}
	if end < 0 || start < 0 || end < start {
		return "bad range in $GENERATE range"
	}

	zp.c.Next() // _BLANK
	// Create a complete new string, which we then parse again.
	s := ""
BuildRR:
	l, _ = zp.c.Next()
	if l.value != zNewline && l.value != zEOF {
		s += l.token
		goto BuildRR
	}

	r := &generateReader{
		file: zp.file,
		lex:  &origL,

		s: s,

		cur:   start,
		start: start,
		end:   end,
		step:  step,
	}
	zp.sub = NewZoneParser(r, zp.origin, zp.file)
	zp.sub.SetDefaultTTL(defaultTtl)
	return ""
}

type generateReader struct {
	file string
	lex  *lex

	s  string
	si int

	cur   int
	start int
	end   int
	step  int

	mod bytes.Buffer

	escape bool

	eof bool
}

func (r *generateReader) parseError(msg string) *ParseError {
	return &ParseError{r.file, msg, *r.lex}
}

func (r *generateReader) Read(p []byte) (int, error) {
	// NewZLexer, through NewZoneParser, should use ReadByte and
	// not end up here.

	panic("not implemented")
}

func (r *generateReader) ReadByte() (byte, error) {
	if r.eof {
		return 0, io.EOF
	}
	if r.mod.Len() > 0 {
		return r.mod.ReadByte()
	}

	if r.si >= len(r.s) {
		r.si = 0
		r.cur += r.step

		r.eof = r.cur > r.end || r.cur < 0
		return '\n', nil
	}

	si := r.si
	r.si++

	switch r.s[si] {
	case '\\':
		if r.escape {
			r.escape = false
			return '\\', nil
		}

		r.escape = true
		return r.ReadByte()
	case '$':
		if r.escape {
			r.escape = false
			return '$', nil
		}

		mod := "%d"

		if si >= len(r.s)-1 {
			// End of the string
			fmt.Fprintf(&r.mod, mod, r.cur)
			return r.mod.ReadByte()
		}

		if r.s[si+1] == '$' {
			r.si++
			return '$', nil
		}

		var offset int

		// Search for { and }
		if r.s[si+1] == '{' {
			// Modifier block
			sep := strings.Index(r.s[si+2:], "}")
			if sep < 0 {
				return 0, r.parseError("bad modifier in $GENERATE")
			}

			var errMsg string
			mod, offset, errMsg = modToPrintf(r.s[si+2 : si+2+sep])
			if errMsg != "" {
				return 0, r.parseError(errMsg)
			}
			if r.start+offset < 0 || r.end+offset > 1<<31-1 {
				return 0, r.parseError("bad offset in $GENERATE")
			}

			r.si += 2 + sep // Jump to it
		}

		fmt.Fprintf(&r.mod, mod, r.cur+offset)
		return r.mod.ReadByte()
	default:
		if r.escape { // Pretty useless here
			r.escape = false
			return r.ReadByte()
		}

		return r.s[si], nil
	}
}

// Convert a $GENERATE modifier 0,0,d to something Printf can deal with.
func modToPrintf(s string) (string, int, string) {
	xs := strings.Split(s, ",")

	// Modifier is { offset [ ,width [ ,base ] ] } - provide default
	// values for optional width and type, if necessary.
	switch len(xs) {
	case 1:
		xs = append(xs, "0", "d")
	case 2:
		xs = append(xs, "d")
	case 3:
	default:
		return "", 0, "bad modifier in $GENERATE"
	}

	// xs[0] is offset, xs[1] is width, xs[2] is base
	if xs[2] != "o" && xs[2] != "d" && xs[2] != "x" && xs[2] != "X" {
		return "", 0, "bad base in $GENERATE"
	}
	offset, err := strconv.Atoi(xs[0])
	if err != nil {
		return "", 0, "bad offset in $GENERATE"
	}
	width, err := strconv.Atoi(xs[1])
	if err != nil || width > 255 {
		return "", offset, "bad width in $GENERATE"
	}
	switch {
	case width < 0:
		return "", offset, "bad width in $GENERATE"
	case width == 0:
		return "%" + xs[1] + xs[2], offset, ""
	}
	return "%0" + xs[1] + xs[2], offset, ""
}
