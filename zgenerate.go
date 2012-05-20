package dns

import (
	"errors"
	"fmt"
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
func generate(l lex, c chan lex, t chan Token, o string) string {
	step := 1
	if i := strings.IndexAny(l.token, "/"); i != -1 {
		if i+1 == len(l.token) {
			return "bad step in $GENERATE range"
		}
		if s, e := strconv.Atoi(l.token[i+1:]); e != nil {
			return "bad step in $GENERATE range"
		} else {
			if s < 0 {
				return "bad step in $GENERATE range"
			}
			step = s
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
	if end < 0 || start < 0 || end <= start {
		return "bad range in $GENERATE range"
	}

	<-c // _BLANK
	// Create a complete new string, which we then parse again.
	s := ""
BuildRR:
	l = <-c
	if l.value != _NEWLINE && l.value != _EOF {
		s += l.token
		goto BuildRR
	}
	for i := start; i <= end; i += step {
		var (
			escape bool
			dom string
			mod string
			offset int
			err error
		)

		for j := 0; j < len(s); j++ { // No 'range' because we need to jump around
			switch s[j] {
			case '\\':
				if escape {
					dom += "\\"
					escape = false
					continue
				}
				escape = true
			case '$':
				mod = "%d"
				offset = 0
				if escape {
					dom += "$"
					escape = false
					continue
				}
				escape = false
				if j+1 >= len(s) { // End of the string
					dom += fmt.Sprintf(mod, i+offset)
					continue
				} else {
					if s[j+1] == '$' {
						dom += "$"
						j++
						continue
					}
				}
				// Search for { and }
				if s[j+1] == '{' { // Modifier block
					sep := strings.Index(s[j+2:], "}")
					if sep == -1 {
						return "bad modifier in $GENERATE"
					}
					//println("checking", s[j+2:j+2+sep])
					mod, offset, err = modToPrintf(s[j+2 : j+2+sep])
					if err != nil {
						return "bad modifier in $GENERATE"
					}
					j += 2 + sep // Jump to it
				}
				//println("mod", mod)
				dom += fmt.Sprintf(mod, i+offset)
			default:
				if escape { // Pretty useless here
					escape = false
					continue
				}
				dom += string(s[j])
			}
		}
		// Re-parse the RR and send it on the current channel t
		rx, err := NewRR("$ORIGIN " + o + "\n" + dom)
		if err != nil {
			return err.(*ParseError).err
		}
		t <- Token{RR: rx}
	}
	return ""
}

// Convert a $GENERATE modifier 0,0,d to something Printf can deal with.
func modToPrintf(s string) (string, int, error) {
	xs := strings.SplitN(s, ",", 3)
	if len(xs) != 3 {
		return "", 0, errors.New("fubar")
	}
	// xs[0] is offset, xs[1] is width, xs[2] is base
	if xs[2] != "o" && xs[2] != "d" && xs[2] != "x" && xs[2] != "X" {
		return "", 0, errors.New("fubar")
	}
	offset, err := strconv.Atoi(xs[0])
	if err != nil {
		return "", 0, err
	}
	width, err := strconv.Atoi(xs[1])
	if err != nil {
		return "", offset, err
	}
	printf := "%"
	switch {
	case width < 0:
		return "", offset, errors.New("fubar")
	case width == 0:
		printf += xs[1]
	default:
		printf += "0" + xs[1]
	}
	printf += xs[2]
	return printf, offset, nil
}
