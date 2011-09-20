package main

import (
	"dns"
)

type itemType int

// We handle the checking as a lexing program.
// We use the lexer like Rob Pike lectures about in this
// clip: http://www.youtube.com/watch?v=HxaD_trXwRE
type item struct {
	typ itemType
	val string
}

const (
	_              itemType = iota
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
	error  string       // error text.
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

// Set the error
func (l *lexer) setError(s string) {
	l.error = s
}

func (l *lexer) run() {
	go func() {
		for l.state != nil {
                        l.state = l.state(l)
		}
		close(l.items)
	}()
}

// "Lexer" functions

// Check if the server responds
func lexAlive(l *lexer) stateFn {
	println("lexAlive")

	//l.fp.SetString("QUERY,NOERROR,qr,aa,tc,RD,ad,cd,z,1,0,0,0,DO,0")
	//l.q = dns.Question{".", dns.TypeNS, dns.ClassINET}
	return lexDoBitMirror
}

// Check if the server returns the DO-bit when set in the request. 
func lexDoBitMirror(l *lexer) stateFn {
	println("lexDoBitMirror")

	// The important part here is that the DO bit is on
	l.setString("QUERY,NOERROR,qr,aa,tc,RD,ad,cd,z,1,0,0,0,DO,0")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)
	if l.probe().Do {
		l.emit(&item{itemSoftware, NSD})
	}
	l.emit(&item{itemSoftware, BIND})
	return nil
}
