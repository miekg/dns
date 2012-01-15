package main

import (
	"dns"
)

const (
	QUERY_NOERROR string = "QUERY,NOERROR,qr,aa,tc,rd,ra,ad,cd,z,0,0,0,0,do,0,nsid"
	QUERY_NOTIFY  string = "NOTIFY,NOERROR,qr,AA,tc,RD,ra,ad,cd,Z,0,0,0,0,do,0,nsid"
	QUERY_ALL     string = "QUERY,NOERROR,QR,AA,TC,RD,RA,AD,CD,Z,0,0,0,0,DO,0,nsid"
)

// Check if the server responds at all
func dnsAlive(l *lexer) stateFn {
	l.debug("Alive")
	l.setString(QUERY_NOERROR)
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)

	f, _ := l.probe()
	if f.ok() {
		return dnsServer
	}
	l.emit(&item{itemError, f.error()})
	return nil
}

// This is the starting test. Perform a bunch of queries, get the
// fingerprint a go into a general direction. NsdLike, BindLike, WindowsLike, MaraLike
func dnsServer(l *lexer) stateFn {
	l.debug("Server")

	// Set the DO bit
	l.setString("QUERY,NOERROR,qr,aa,tc,RD,ra,ad,cd,z,0,0,0,0,DO,4097,NSID")
	l.setQuestion(".", dns.TypeTXT, dns.ClassCHAOS)
	f,_ := l.probe()
	switch {
	case !f.Do && f.UDPSize == 4096 && f.Rcode == dns.RcodeSuccess:
		// NSD clears DO bit, but sets UDPSize to 4096. NOERROR.
		l.emit(&item{itemVendor, NLNETLABS})
		return dnsNsdLike
	case !f.Do && f.UDPSize == 0 && f.Rcode == dns.RcodeRefused:
		// MaraDNS clears DO BIT, UDPSize to 0. REFUSED
		l.emit(&item{itemVendor, MARA})
		return dnsMaraLike
	case !f.Do && f.UDPSize == 0 && f.Rcode == dns.RcodeSuccess:
		// PowerDNS(SEC) clears DO bit, resets UDPSize. NOERROR
		l.emit(&item{itemVendor, POWER})
		return dnsPowerdnsLike
	case !f.Do && f.UDPSize == 0 && f.Rcode == dns.RcodeServerFailure:
		// Neustar or UltraDNS Resolver
		l.emit(&item{itemVendor, NEUSTAR})
		return dnsNeustarLike
	case !f.Do && f.UDPSize == 0 && f.Rcode == dns.RcodeNotImplemented:
		// Altas?
		l.emit(&item{itemVendor, VERISIGN})
		return dnsAtlasLike
	case !f.Do && f.UDPSize == 4096 && f.Rcode == dns.RcodeServerFailure:
		// BIND8
		fallthrough
	case f.Do && f.UDPSize == 4096 && f.Rcode == dns.RcodeServerFailure:
		// BIND9 OLD
		fallthrough
	case f.Do && f.UDPSize == 4096 && f.Rcode == dns.RcodeRefused:
		// BIND9 leaves DO bit, but sets UDPSize to 4096. REFUSED.
		l.emit(&item{itemVendor, ISC})
		return dnsBindLike
	case f.Do && f.UDPSize == 4097 && f.Rcode == dns.RcodeFormatError:
		// Microsoft leaves DO bit, but echo's the UDPSize. FORMERR.
		l.emit(&item{itemVendor, MICROSOFT})
		return dnsWindowsLike
	default:
		return nil
	}
	panic("not reached")
	return nil
}

func dnsNsdLike(l *lexer) stateFn {
	l.debug("NsdLike")
	l.setString(QUERY_NOERROR)
	l.setQuestion("authors.bind.", dns.TypeTXT, dns.ClassCHAOS)
	l.probe()

	return nil
}

func dnsBindLike(l *lexer) stateFn {
	l.debug("BindLike")

	l.emit(&item{itemSoftware, BIND})

	// Repeat the query, as we get a lot of information from it
	l.setString("QUERY,NOERROR,qr,aa,tc,RD,ra,ad,cd,z,0,0,0,0,DO,4097,nsid")
	l.setQuestion(".", dns.TypeTXT, dns.ClassCHAOS)
	f, _ := l.probe()
	switch {
	case !f.Do && f.UDPSize == 4096 && f.Rcode == dns.RcodeServerFailure:
		l.emit(&item{itemVersionMajor, "8"})
	case f.Do && f.UDPSize == 4096 && f.Rcode == dns.RcodeServerFailure:
		l.emit(&item{itemVersionMajor, "9"})
		l.emit(&item{itemVersionMinor, "3"})
	case f.Do && f.UDPSize == 4096 && f.Rcode == dns.RcodeRefused:
		// BIND9 leaves DO bit, but sets UDPSize to 4096. REFUSED.
		l.emit(&item{itemVersionMajor, "9"})
		l.emit(&item{itemVersionMinor, "[7..]"})
	}

	// Try authors.bind
	l.setString(QUERY_NOERROR)
	l.setQuestion("authors.bind.", dns.TypeTXT, dns.ClassCHAOS)
	f, _ = l.probe()
	switch f.Rcode {
	case dns.RcodeServerFailure:
		// No authors.bind < 9
		l.emit(&item{itemVersionMajor, "8"})
	case dns.RcodeSuccess, dns.RcodeRefused:
		// BIND 9 or BIND 10
		l.emit(&item{itemVersionMajor, "[9..10]"})
	}
	// The three BIND (8, 9 and 10) behave differently when
	// receiving a notify query
	l.setString(QUERY_NOTIFY)
	l.setQuestion("bind.", dns.TypeSOA, dns.ClassNONE)
	f, _ = l.probe()
	switch {
	case f.Opcode == dns.OpcodeNotify:
		if f.Rcode == dns.RcodeRefused {
			l.emit(&item{itemVersionMajor, "9"})
		}
		if f.Rcode == dns.RcodeServerFailure {
			l.emit(&item{itemVersionMajor, "8"})
		}
	case f.Opcode == dns.OpcodeQuery && f.Rcode == dns.RcodeSuccess:
		l.emit(&item{itemVersionMajor, "10"})
		if !f.Response {
			// Cardinal sin
			l.emit(&item{itemVersionMinor, "-devel"})
			l.emit(&item{itemVersionPatch, "20110809"})
		}
	}
	return nil
}

func dnsWindowsLike(l *lexer) stateFn {
	l.debug("WindowsLike")

	return nil
}

func dnsMaraLike(l *lexer) stateFn {
	l.debug("MaraLike")

	return nil
}

func dnsPowerdnsLike(l *lexer) stateFn {
	l.debug("PowerdnsLike")
	return nil
}

func dnsYadifaLike(l *lexer) stateFn {
	l.debug("YadifaLike")
	l.setString(".,CLASS0,TYPE0,QUERY,NOERROR,QR,aa,tc,rd,ra,ad,cd,z,0,0,0,0,do,0,nsid")
	l.probe()
	l.setString(".,CLASS42,TXT,QUERY,NOERROR,qr,aa,tc,rd,ra,ad,cd,z,0,0,0,0,do,0,nsid")
	l.probe()
	return nil
}

func dnsNeustarLike(l *lexer) stateFn {
	l.debug("NeustarLike")
        l.debug("UltraDNS")
	l.setString(".,CLASS42,TXT,QUERY,NOERROR,qr,aa,tc,rd,ra,ad,cd,z,0,0,0,0,do,0,nsid")
	l.probe()

	return nil
}

func dnsAtlasLike(l *lexer) stateFn {
	l.debug("AtlasLike")

	return nil
}

// Check if the server returns the DO-bit when set in the request.                                                                          
func dnsDoBitMirror(l *lexer) stateFn {
	l.debug("DoBitMirror")

	l.setString("QUERY,NOERROR,qr,aa,tc,RD,ra,ad,cd,z,0,0,0,0,DO,0,NSID")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)

	f, _ := l.probe()
	// NSD doesn't set the DO bit, but does set the UDPMsg size to 4096.
	if !f.Do && f.UDPSize == 4096 {
		l.emit(&item{itemSoftware, NSD})
		return dnsEDNS0Mangler
	}
	return dnsEDNS0Mangler
}

func dnsEDNS0Mangler(l *lexer) stateFn {
	l.debug("EDNS0Mangler")
	l.setString("NOTIFY,NOERROR,qr,aa,tc,RD,ra,ad,cd,z,0,0,0,0,do,0,nsid")
	l.setQuestion("012345678901234567890123456789012345678901234567890123456789012.012345678901234567890123456789012345678901234567890123456789012.012345678901234567890123456789012345678901234567890123456789012.0123456789012345678901234567890123456789012345678901234567890.", dns.TypeA, dns.ClassINET)
	f, _ := l.probe()
	// MaraDNS does not set the QR bit in the reply... but only with this question is seems
	// QUERY,NOERROR,qr,aa,t
	if !f.Response && f.Opcode == dns.OpcodeQuery && f.Rcode == dns.RcodeSuccess {
		l.emit(&item{itemSoftware, MARADNS})
	}
	return dnsTcEnable
}

func dnsTcEnable(l *lexer) stateFn {
	l.debug("TcEnable")
	l.setString("QUERY,NOERROR,qr,aa,TC,rd,ra,ad,cd,z,0,0,0,0,do,0,nsid")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)
	l.probe()
	return dnsUDPSize
}

func dnsUDPSize(l *lexer) stateFn {
	l.debug("UDPSize")
	l.setString("QUERY,NOERROR,qr,aa,tc,rd,ra,ad,cd,z,0,0,0,0,DO,4097,nsid")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)
	l.probe()
	return dnsZero
}

func dnsZero(l *lexer) stateFn {
	l.debug("Zero")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)
	l.setString("QUERY,NOERROR,qr,aa,tc,rd,ra,ad,cd,Z,0,0,0,0,do,0,nsid")
	l.probe()
	return dnsAll
}

func dnsAll(l *lexer) stateFn {
	l.debug("All")
	l.setString("QUERY,NOERROR,qr,AA,TC,RD,RA,AD,CD,Z,0,0,0,0,DO,8192,nsid")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)
	l.probe()
	return dnsIquery
}

func dnsIquery(l *lexer) stateFn {
	l.debug("Iquery")
	l.setString("IQUERY,NOERROR,qr,aa,tc,rd,ra,ad,cd,Z,0,0,0,0,do,0,nsid")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)
	l.probe()
	return dnsUpdate
}

func dnsUpdate(l *lexer) stateFn {
	l.debug("Update")
	l.setString("UPDATE,NOERROR,qr,aa,tc,rd,ra,ad,cd,Z,0,0,0,0,do,0,nsid")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)
	l.probe()
	return dnsStatus
}

func dnsStatus(l *lexer) stateFn {
	l.debug("Status")
	l.setString("STATUS,NOERROR,qr,aa,tc,rd,ra,ad,cd,Z,0,0,0,0,do,0,nsid")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)
	l.probe()
	return dnsOpcodeWhacky
}

func dnsOpcodeWhacky(l *lexer) stateFn {
	l.debug("OpcodeWhacky")
	l.setString("12,NOERROR,qr,aa,tc,rd,ra,ad,cd,Z,0,0,0,0,do,0,nsid")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)
	l.probe()
	return dnsRcodeWhacky
}

func dnsRcodeWhacky(l *lexer) stateFn {
	l.debug("RcodeWhacky")
	l.setString("QUERY,31,qr,aa,tc,rd,ra,ad,cd,Z,0,0,0,0,do,0,nsid")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)
	l.probe()
	return dnsRcodeNotZone
}

func dnsRcodeNotZone(l *lexer) stateFn {
	l.debug("RcodeNotZone")
	l.setString("QUERY,NOTZONE,qr,aa,tc,rd,ra,ad,cd,z,0,0,0,0,do,0,nsid")
	l.setQuestion(".", dns.TypeNS, dns.ClassINET)
	l.probe()
	return nil
}
