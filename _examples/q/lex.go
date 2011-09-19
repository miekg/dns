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
	itemError    itemType = iota
	itemVender            // software vendor
	itemSoftware          // the name of the DNS server software
	itemVersionMin           // the minimum version of the software (empty if not determined)
	itemVersionMax           // the maximum version of the software (empty if not determined)
)

// stateFn represents the state of the scanner as a function that returns the next state.
type stateFn func(*lexer) stateFn

type lexer struct {
	client *dns.Client  // client used.
	addr   string       // addr of the server being scanned.
	fp     *fingerprint       // fingerprint to test.
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

// "Lexer" functions

// Check if the server returns the DO-bit when set in the request. 
func lexDoBitMirror(l *lexer) stateFn {
	// The important part here is that the DO bit is on
	l.fp.SetString("QUERY,NOERROR,qr,aa,tc,RD,ad,cd,z,1,0,0,0,DO,0")
	l.q = dns.Question{".", dns.TypeNS, dns.ClassINET}
        if l.probe().Do {
                println(NSD)
        //        l.emit(&item{itemSoftware, NSD})
        }
        //l.emit(&item{itemSoftware, BIND})
        println(BIND)
	return nil
}
