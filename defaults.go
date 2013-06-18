// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"net"
	"strconv"
	"strings"
)

const hexDigit = "0123456789abcdef"

// Everything is assumed in the ClassINET class. If
// you need other classes you are on your own.

// SetReply creates a reply packet from a request message.
func (dns *Msg) SetReply(request *Msg) *Msg {
	dns.Id = request.Id
	dns.RecursionDesired = request.RecursionDesired // Copy rd bit
	dns.Response = true
	dns.Opcode = OpcodeQuery
	dns.Rcode = RcodeSuccess
	if len(request.Question) > 0 {
		dns.Question = make([]Question, 1)
		dns.Question[0] = request.Question[0]
	}
	return dns
}

// SetQuestion creates a question packet.
func (dns *Msg) SetQuestion(z string, t uint16) *Msg {
	dns.Id = Id()
	dns.RecursionDesired = true
	dns.Question = make([]Question, 1)
	dns.Question[0] = Question{z, t, ClassINET}
	return dns
}

// SetNotify creates a notify packet.
func (dns *Msg) SetNotify(z string) *Msg {
	dns.Opcode = OpcodeNotify
	dns.Authoritative = true
	dns.Id = Id()
	dns.Question = make([]Question, 1)
	dns.Question[0] = Question{z, TypeSOA, ClassINET}
	return dns
}

// SetRcode creates an error packet suitable for the request.
func (dns *Msg) SetRcode(request *Msg, rcode int) *Msg {
	dns.Rcode = rcode
	dns.Opcode = OpcodeQuery
	dns.Response = true
	dns.Id = request.Id
	// Note that this is actually a FORMERR
	if len(request.Question) > 0 {
		dns.Question = make([]Question, 1)
		dns.Question[0] = request.Question[0]
	}
	return dns
}

// SetRcodeFormatError creates a packet with FormError set.
func (dns *Msg) SetRcodeFormatError(request *Msg) *Msg {
	dns.Rcode = RcodeFormatError
	dns.Opcode = OpcodeQuery
	dns.Response = true
	dns.Authoritative = false
	dns.Id = request.Id
	return dns
}

// SetUpdate makes the message a dynamic update packet. It
// sets the ZONE section to: z, TypeSOA, ClassINET.
func (dns *Msg) SetUpdate(z string) *Msg {
	dns.Id = Id()
	dns.Response = false
	dns.Opcode = OpcodeUpdate
	dns.Compress = false // BIND9 cannot handle compression
	dns.Question = make([]Question, 1)
	dns.Question[0] = Question{z, TypeSOA, ClassINET}
	return dns
}

// SetIxfr creates dns.Msg for requesting an IXFR.
func (dns *Msg) SetIxfr(z string, serial uint32) *Msg {
	dns.Id = Id()
	dns.Question = make([]Question, 1)
	dns.Ns = make([]RR, 1)
	s := new(SOA)
	s.Hdr = RR_Header{z, TypeSOA, ClassINET, defaultTtl, 0}
	s.Serial = serial
	dns.Question[0] = Question{z, TypeIXFR, ClassINET}
	dns.Ns[0] = s
	return dns
}

// SetAxfr creates dns.Msg for requesting an AXFR.
func (dns *Msg) SetAxfr(z string) *Msg {
	dns.Id = Id()
	dns.Question = make([]Question, 1)
	dns.Question[0] = Question{z, TypeAXFR, ClassINET}
	return dns
}

// SetTsig appends a TSIG RR to the message.
// This is only a skeleton TSIG RR that is added as the last RR in the
// additional section. The Tsig is calculated when the message is being send.
func (dns *Msg) SetTsig(z, algo string, fudge, timesigned int64) *Msg {
	t := new(TSIG)
	t.Hdr = RR_Header{z, TypeTSIG, ClassANY, 0, 0}
	t.Algorithm = algo
	t.Fudge = 300
	t.TimeSigned = uint64(timesigned)
	t.OrigId = dns.Id
	dns.Extra = append(dns.Extra, t)
	return dns
}

// SetEdns0 appends a EDNS0 OPT RR to the message.
// TSIG should always the last RR in a message.
func (dns *Msg) SetEdns0(udpsize uint16, do bool) *Msg {
	e := new(OPT)
	e.Hdr.Name = "."
	e.Hdr.Rrtype = TypeOPT
	e.SetUDPSize(udpsize)
	if do {
		e.SetDo()
	}
	dns.Extra = append(dns.Extra, e)
	return dns
}

// IsTsig checks if the message has a TSIG record as the last record
// in the additional section. It returns the TSIG record found or nil.
func (dns *Msg) IsTsig() *TSIG {
	if len(dns.Extra) > 0 {
		if dns.Extra[len(dns.Extra)-1].Header().Rrtype == TypeTSIG {
			return dns.Extra[len(dns.Extra)-1].(*TSIG)
		}
	}
	return nil
}

// IsEdns0 checks if the message has a EDNS0 (OPT) record, any EDNS0
// record in the additional section will do. It returns the OPT record
// found or nil.
func (dns *Msg) IsEdns0() *OPT {
	for _, r := range dns.Extra {
		if r.Header().Rrtype == TypeOPT {
			return r.(*OPT)
		}
	}
	return nil
}

// IsDomainName checks if s is a valid domainname, it returns
// the number of labels, total length and true, when a domain name is valid.
// When false is returned the labelcount and length are not defined.
func IsDomainName(s string) (uint8, uint8, bool) { // copied from net package.
	// TODO(mg): check for \DDD - seems to work fine without though
	// See RFC 1035, RFC 3696.
	l := len(s)
	if l == 0 || l > 255 {
		return 0, 0, false
	}
	longer := 0
	// Simplify checking loop: make the name end in a dot.
	// Don't call Fqdn() to save another len(s).
	// Keep in mind that if we do this, otherwise we report a length+1
	if s[l-1] != '.' {
		s += "."
		l++
		longer = 1
	}
	// Preloop check for root label
	if s == "." {
		return 0, 1, true
	}

	last := byte('.')
	ok := false // ok once we've seen a letter or digit
	partlen := 0
	labels := uint8(0)
	var c byte
	for i := 0; i < l; i++ {
		c = s[i]
		switch {
		default:
			// anything escaped is legal
			if last != '\\' {
				return 0, uint8(l - longer), false
			}
			partlen++
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_' || c == '*' || c == '/':
			ok = true
			partlen++
		case c == '\\': // OK
		case c == '@':
			if last != '\\' {
				return 0, uint8(l - longer), false
			}
			partlen++
		case '0' <= c && c <= '9':
			ok = true
			partlen++
		case c == '-':
			// byte before dash cannot be dot
			if last == '.' {
				return 0, uint8(l - longer), false
			}
			partlen++
		case c == '.':
			// byte before dot cannot be dot
			if last == '.' {
				return 0, uint8(l - longer), false
			}
			if last == '\\' { // Ok, escaped dot.
				partlen++
				c = 'A' // make current value not scary
				break
			}
			if partlen > 63 || partlen == 0 {
				return 0, uint8(l - longer), false
			}
			partlen = 0
			labels++
		}
		last = c
	}
	return labels, uint8(l - longer), ok
}

// IsSubDomain checks if child is indeed a child of the parent.
func IsSubDomain(parent, child string) bool {
	// Entire child is contained in parent
	return CompareLabels(strings.ToLower(parent), strings.ToLower(child)) == LenLabels(parent)
}

// IsFqdn checks if a domain name is fully qualified.
func IsFqdn(s string) bool {
	l := len(s)
	if l == 0 {
		return false // ?
	}
	return s[l-1] == '.'
}

// Fqdns return the fully qualified domain name from s.
// If s is already fully qualified, it behaves as the identity function.
func Fqdn(s string) string {
	if IsFqdn(s) {
		return s
	}
	return s + "."
}

// Copied from the official Go code

// ReverseAddr returns the in-addr.arpa. or ip6.arpa. hostname of the IP
// address addr suitable for rDNS (PTR) record lookup or an error if it fails
// to parse the IP address.
func ReverseAddr(addr string) (arpa string, err error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", &Error{Err: "unrecognized address", Name: addr}
	}
	if ip.To4() != nil {
		return strconv.Itoa(int(ip[15])) + "." + strconv.Itoa(int(ip[14])) + "." + strconv.Itoa(int(ip[13])) + "." +
			strconv.Itoa(int(ip[12])) + ".in-addr.arpa.", nil
	}
	// Must be IPv6
	buf := make([]byte, 0, len(ip)*4+len("ip6.arpa."))
	// Add it, in reverse, to the buffer
	for i := len(ip) - 1; i >= 0; i-- {
		v := ip[i]
		buf = append(buf, hexDigit[v&0xF])
		buf = append(buf, '.')
		buf = append(buf, hexDigit[v>>4])
		buf = append(buf, '.')
	}
	// Append "ip6.arpa." and return (buf already has the final .)
	buf = append(buf, "ip6.arpa."...)
	return string(buf), nil
}

// String returns the string representation for the type t
func (t Type) String() string {
	if t1, ok := TypeToString[uint16(t)]; ok {
		return t1
	} else {
		return "TYPE" + strconv.Itoa(int(t))
	}
	panic("dns: not reached") // go < 1.1 compat
}

// String returns the string representation for the class c
func (c Class) String() string {
	if c1, ok := ClassToString[uint16(c)]; ok {
		return c1
	} else {
		return "CLASS" + strconv.Itoa(int(c))
	}
	panic("dns: not reached")
}
