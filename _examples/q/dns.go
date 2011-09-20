package main

import (
	"dns"
)

// Check if the server responds at all
func dnsAlive(l *lexer) stateFn {
	l.verbose("Alive")
	l.setString("QUERY,NOERROR,qr,aa,tc,rd,ra,ad,cd,z,0,0,0,0,do,0")
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
	l.setString("QUERY,NOERROR,qr,aa,tc,RD,ra,ad,cd,z,0,0,0,0,DO,0")
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
	l.setString("NOTIFY,NOERROR,qr,aa,tc,RD,ra,ad,cd,z,0,0,0,0,do,0")
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
	l.setString("QUERY,NOERROR,qr,aa,TC,rd,ra,ad,cd,z,0,0,0,0,do,0")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)
	l.probe()
	return dnsUDPSize
}

func dnsUDPSize(l *lexer) stateFn {
	l.verbose("UDPSize")
	l.setString("QUERY,NOERROR,qr,aa,tc,rd,ra,ad,cd,z,0,0,0,0,DO,4097")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)
	l.probe()
	return dnsZero
}

func dnsZero(l *lexer) stateFn {
	l.verbose("Zero")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)
	l.setString("QUERY,NOERROR,qr,aa,tc,rd,ra,ad,cd,Z,0,0,0,0,do,0")
	l.probe()
	return dnsAll
}

func dnsAll(l *lexer) stateFn {
	l.verbose("All")
	l.setString("QUERY,NOERROR,qr,AA,TC,RD,RA,AD,CD,Z,0,0,0,0,DO,8192")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)
	l.probe()
	return dnsIquery
}

func dnsIquery(l *lexer) stateFn {
	l.verbose("Iquery")
	l.setString("IQUERY,NOERROR,qr,aa,tc,rd,ra,ad,cd,Z,0,0,0,0,do,0")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)
	l.probe()
	return dnsUpdate
}

func dnsUpdate(l *lexer) stateFn {
	l.verbose("Update")
	l.setString("UPDATE,NOERROR,qr,aa,tc,rd,ra,ad,cd,Z,0,0,0,0,do,0")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)
	l.probe()
	return dnsStatus
}

func dnsStatus(l *lexer) stateFn {
	l.verbose("Status")
	l.setString("STATUS,NOERROR,qr,aa,tc,rd,ra,ad,cd,Z,0,0,0,0,do,0")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)
	l.probe()
	return dnsOpcodeWhacky
}

func dnsOpcodeWhacky(l *lexer) stateFn {
	l.verbose("OpcodeWhacky")
	l.setString("12,NOERROR,qr,aa,tc,rd,ra,ad,cd,Z,0,0,0,0,do,0")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)
	l.probe()
	return dnsRcodeWhacky
}

func dnsRcodeWhacky(l *lexer) stateFn {
	l.verbose("RcodeWhacky")
	l.setString("QUERY,31,qr,aa,tc,rd,ra,ad,cd,Z,0,0,0,0,do,0")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)
	l.probe()
	return dnsRcodeNotZone
}

func dnsRcodeNotZone(l *lexer) stateFn {
	l.verbose("RcodeNotZone")
	l.setString("QUERY,NOTZONE,qr,aa,tc,rd,ra,ad,cd,Z,0,0,0,0,do,0")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)
	l.probe()
	return nil
}
