// We handle the checking as a lexing program.
// We use the lexer like Rob Pike lectures about in this
// clip: http://www.youtube.com/watch?v=HxaD_trXwRE

package main

import (
	"dns"
	"fmt"
)

type itemType int

type item struct {
	typ itemType
	val string
}

const (
	itemError        itemType = iota
	itemSoftware              // the name of the DNS server software
	itemVendor                // vendor of the DNS software
	itemVersionMajor          // the major version of the software (empty if not determined)
	itemVersionMinor          // the minor version of the software (empty if not determined)
	itemVersionPatch          // the patch level of the software (empty if not determined)
)

var itemString = map[itemType]string{
	itemError:        "error",
	itemSoftware:     "software",
	itemVendor:       "vendor",
	itemVersionMajor: "major",
	itemVersionMinor: "minor",
	itemVersionPatch: "patch",
}

// stateFn represents the state of the scanner as a function that returns the next state.
type stateFn func(*lexer) stateFn

type lexer struct {
	client    *dns.Client  // client used.
	addr      string       // addr of the server being scanned.
	fp        *fingerprint // fingerprint to test.
	q         dns.Question // question to ask.
	items     chan item    // channel of scanned items.
	state     stateFn      // the next function to enter.
	verbose   bool         // if true, the fingerprints are printed.
	debugging bool         // If true, print the function names.
}

func (l *lexer) probe() (*fingerprint, dns.Question) {
	f, q := sendProbe(l.client, l.addr, l.fp, l.q)
	if l.verbose {
		fmt.Printf("QR : %s\t-", f)
		fmt.Printf(" (%s)\n", q.String())
	}
	return f, q
}

func (l *lexer) emit(i *item) {
	l.items <- *i
}

func (l *lexer) setString(s string) {
	l.fp.setString(s)
	if l.verbose {
		fmt.Printf("Q  : %s\t-", s)
	}
}

func (l *lexer) setQuestion(name string, t uint16, c uint16) {
	l.q = dns.Question{name, t, c}
	if l.verbose {
		fmt.Printf(" (%s)\n", l.q.String())
	}
}

func (l *lexer) run() {
	go func() {
		for l.state != nil {
			l.state = l.state(l)
		}
		close(l.items)
	}()
}

func (l *lexer) debug(s string) {
	if l.debugging {
		fmt.Printf(" dns%s\n", s)
	}
}
