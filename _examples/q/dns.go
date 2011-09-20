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
	l.setString("QUERY,NOERROR,qr,aa,tc,RD,ra,ad,cd,z,1,0,0,0,DO,0")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)

	f := l.probe()
	// NSD doesn't set the DO bit, but does set the UDPMsg size to 4096.
	if !f.Do && f.UDPSize == 4096 {
		l.emit(&item{itemSoftware, NSD})
		return dnsEDNS0Mangler
	}
	return dnsEDNS0Mangler
}

func dnsEDNS0Mangler(l *lexer) stateFn {
	l.verbose("EDNS0Mangler")
	l.setString("NOTIFY,NOERROR,qr,aa,tc,RD,ra,ad,cd,z,1,0,0,0,do,0")
	l.setQuestion("012345678901234567890123456789012345678901234567890123456789012.012345678901234567890123456789012345678901234567890123456789012.012345678901234567890123456789012345678901234567890123456789012.0123456789012345678901234567890123456789012345678901234567890.", dns.TypeA, dns.ClassINET)
	f := l.probe()
        // MaraDNS does not set the QR bit in the reply... but only with this question is seems
        // QUERY,NOERROR,qr,aa,t
        if !f.Response && f.Opcode == dns.OpcodeQuery && f.Rcode == dns.RcodeSuccess {
	        l.emit(&item{itemSoftware, MARADNS})
        }
	return dnsTcEnable
}

func dnsTcEnable(l *lexer) stateFn {
	l.verbose("TcEnable")
	l.setString("QUERY,NOERROR,qr,aa,TC,rd,ra,ad,cd,z,1,0,0,0,do,0")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)

	f := l.probe()
        f = f
	return nil
}
