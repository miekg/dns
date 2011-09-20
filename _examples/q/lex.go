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
	itemVender              // software vendor
	itemSoftware            // the name of the DNS server software
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
}

func (l *lexer) probe() *fingerprint {
	return sendProbe(l.client, l.addr, l.fp, l.q)
}

func (l *lexer) emit(i *item) {
	l.items <- *i
}

func (l *lexer) setString(s string) {
	l.fp.setString(s)
}

func (l *lexer) setQuestion(name string, t uint16, c uint16) {
	l.q = dns.Question{name, t, c}
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
        fmt.Printf("running: dns%s\n", s)
}

// "Lexer" functions, prefixed with dns

// Check if the server responds at all
func dnsAlive(l *lexer) stateFn {
	l.verbose("Alive")
	l.setString("QUERY,NOERROR,qr,aa,tc,rd,ad,cd,z,1,0,0,0,do,0")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)

	f := l.probe()

	if f.ok() {
		return dnsDoBitMirror
	}
	l.emit(&item{itemError, f.error()})
	return nil
}

// Check if the server returns the DO-bit when set in the request. 
func dnsDoBitMirror(l *lexer) stateFn {
	l.verbose("DoBitMirror")
	// The important part here is that the DO bit is on in the reply
	l.setString("QUERY,NOERROR,qr,aa,tc,RD,ad,cd,z,1,0,0,0,DO,0")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)

	f := l.probe()
	if !f.Do {
		l.emit(&item{itemSoftware, NSD})
                return nil
	}
	l.emit(&item{itemSoftware, BIND})
	return nil
}
