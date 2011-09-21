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
	itemError      itemType = iota
	itemSoftware            // the name of the DNS server software
	itemVendor              // vendor of the DNS software
	itemVersionMin          // the minimum version of the software (empty if not determined)
	itemVersionMax          // the maximum version of the software (empty if not determined)
)

// stateFn represents the state of the scanner as a function that returns the next state.
type stateFn func(*lexer) stateFn

type lexer struct {
	client *dns.Client  // client used.
	addr   string       // addr of the server being scanned.
	fp     *fingerprint // fingerprint to test.
	q      dns.Question // question to ask.
	items  chan item    // channel of scanned items.
	state  stateFn      // the next function to enter.
	debug  bool         // if true, the fingerprints are printed.
}

func (l *lexer) probe() *fingerprint {
	f := sendProbe(l.client, l.addr, l.fp, l.q)
	if l.debug {
		fmt.Printf("      QR fp: %s\n", f)
	}
	return f
}

func (l *lexer) emit(i *item) {
	l.items <- *i
}

func (l *lexer) setString(s string) {
	l.fp.setString(s)
	if l.debug {
		fmt.Printf("       Q fp: %s\n", s)
	}
}

func (l *lexer) setQuestion(name string, t uint16, c uint16) {
	l.q = dns.Question{name, t, c}
        if l.debug {
                fmt.Printf("             %s\n", l.q.String())
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

func (l *lexer) verbose(s string) {
	if l.debug {
		fmt.Printf(" dns%s\n", s)
	}
}
