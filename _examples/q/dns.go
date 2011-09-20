package main

import (
	"dns"
)

// Check if the server responds at all
func dnsAlive(l *lexer) stateFn {
	l.verbose("Alive")
	l.setString("QUERY,NOERROR,qr,aa,tc,rd,ra,ad,cd,z,1,0,0,0,do,0")
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
	l.setString("QUERY,NOERROR,qr,aa,tc,RD,ra,ad,cd,z,1,0,0,0,DO,0")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)

	f := l.probe()
	if !f.Do {
		l.emit(&item{itemSoftware, NSD})
		return nil
	}
	l.emit(&item{itemSoftware, BIND})
	return nil
}
