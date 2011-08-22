package dns

// Everything is assumed in the ClassINET class. If
// you need other classes you are on your own.

// Create a reply packet from a request message.
func (dns *Msg) SetReply(request *Msg) {
	dns.MsgHdr.Id = request.MsgHdr.Id
	dns.MsgHdr.Authoritative = true
	dns.MsgHdr.Response = true
	dns.MsgHdr.Opcode = OpcodeQuery
	dns.MsgHdr.Rcode = RcodeSuccess
	dns.Question = make([]Question, 1)
	dns.Question[0] = request.Question[0]
}

// Create a question packet.
func (dns *Msg) SetQuestion(z string, t uint16) {
	dns.MsgHdr.Id = Id()
	dns.MsgHdr.RecursionDesired = true
	dns.Question = make([]Question, 1)
	dns.Question[0] = Question{z, t, ClassINET}
}

// Create a notify packet.
func (dns *Msg) SetNotify(z string) {
	dns.MsgHdr.Opcode = OpcodeNotify
	dns.MsgHdr.Authoritative = true
	dns.MsgHdr.Id = Id()
	dns.Question = make([]Question, 1)
	dns.Question[0] = Question{z, TypeSOA, ClassINET}
}

// Create an error packet.
func (dns *Msg) SetRcode(request *Msg, rcode int) {
        dns.MsgHdr.Rcode = rcode
        dns.MsgHdr.Opcode = OpcodeQuery
        dns.MsgHdr.Response = true
        dns.MsgHdr.Authoritative = false
        dns.MsgHdr.Id = request.MsgHdr.Id
        dns.Question = make([]Question, 1)
        dns.Question[0] = request.Question[0]
}

// IsRcode checks if the header of the packet has rcode set.
func (dns *Msg) IsRcode(rcode int) (ok bool) {
	if len(dns.Question) == 0 {
		return false
	}
        ok = dns.MsgHdr.Rcode == rcode
        return
}

// Create a packet with FormError set.
func (dns *Msg) SetRcodeFormatError(request *Msg) {
        dns.MsgHdr.Rcode = RcodeFormatError
        dns.MsgHdr.Opcode = OpcodeQuery
        dns.MsgHdr.Response = true
        dns.MsgHdr.Authoritative = false
        dns.MsgHdr.Id = request.MsgHdr.Id
}

// IsQuestion returns true if the the packet is a question.
func (dns *Msg) IsQuestion() (ok bool) {
        if len(dns.Question) == 0 {
                return false
        }
        ok = dns.MsgHdr.Response == false
        return
}

// Is the message a packet with the FormErr set?
func (dns *Msg) IsRcodeFormatError() (ok bool) {
	if len(dns.Question) == 0 {
		return false
	}
        ok = dns.MsgHdr.Rcode == RcodeFormatError
        return
}

// IsUpdate checks if the message is a dynamic update packet?
func (dns *Msg) IsUpdate() (ok bool) {
	if len(dns.Question) == 0 {
		return false
	}
	ok = dns.MsgHdr.Opcode == OpcodeUpdate
	ok = ok && dns.Question[0].Qtype == TypeSOA
	return
}

// SetUpdate makes the message a dynamic update packet. It
// sets the ZONE section to: z, TypeSOA, classINET.
func (dns *Msg) SetUpdate(z string) {
        dns.MsgHdr.Id = Id()
        dns.MsgHdr.Opcode = OpcodeUpdate
	dns.Question = make([]Question, 1)
	dns.Question[0] = Question{z, TypeSOA, ClassINET}
}

// Is the message a valid notify packet?
func (dns *Msg) IsNotify() (ok bool) {
	if len(dns.Question) == 0 {
		return false
	}
	ok = dns.MsgHdr.Opcode == OpcodeNotify
	ok = ok && dns.Question[0].Qclass == ClassINET
	ok = ok && dns.Question[0].Qtype == TypeSOA
	return
}

// Create a dns msg suitable for requesting an ixfr.
func (dns *Msg) SetIxfr(z string, serial uint32) {
	dns.MsgHdr.Id = Id()
	dns.Question = make([]Question, 1)
	dns.Ns = make([]RR, 1)
	s := new(RR_SOA)
	s.Hdr = RR_Header{z, TypeSOA, ClassINET, DefaultTTL, 0}
	s.Serial = serial

	dns.Question[0] = Question{z, TypeIXFR, ClassINET}
	dns.Ns[0] = s
}

// Create a dns msg suitable for requesting an axfr.
func (dns *Msg) SetAxfr(z string) {
	dns.MsgHdr.Id = Id()
	dns.Question = make([]Question, 1)
	dns.Question[0] = Question{z, TypeAXFR, ClassINET}
}

// Is the message a valid axfr request packet?
func (dns *Msg) IsAxfr() (ok bool) {
	if len(dns.Question) == 0 {
		return false
	}
	ok = dns.MsgHdr.Opcode == OpcodeQuery
	ok = ok && dns.Question[0].Qclass == ClassINET
	ok = ok && dns.Question[0].Qtype == TypeAXFR
	return
}

// Is the message a valid ixfr request packet?
func (dns *Msg) IsIxfr() (ok bool) {
	if len(dns.Question) == 0 {
		return false
	}
	ok = dns.MsgHdr.Opcode == OpcodeQuery
	ok = ok && dns.Question[0].Qclass == ClassINET
	ok = ok && dns.Question[0].Qtype == TypeIXFR
	return
}

// Has the message a TSIG record as the last record?
func (dns *Msg) IsTsig() (ok bool) {
	if len(dns.Extra) > 0 {
		return dns.Extra[0].Header().Rrtype == TypeTSIG
	}
	return
}

// SetTsig Calculates and appends a TSIG RR on the message.
func (dns *Msg) SetTsig(z, algo string, fudge uint16, timesigned uint64) {
	t := new(RR_TSIG)
	t.Hdr = RR_Header{z, TypeTSIG, ClassANY, 0, 0}
	t.Algorithm = algo
	t.Fudge = fudge
	t.TimeSigned = timesigned
	dns.Extra = append(dns.Extra, t)
}

// IsDomainName checks if s is a valid domainname.
func IsDomainName(s string) bool { // copied from net package.
	// See RFC 1035, RFC 3696.
	if len(s) == 0 {
		return false
	}
	if len(s) > 255 {
		return false
	}
	if s[len(s)-1] != '.' { // simplify checking loop: make name end in dot
		s += "."
	}

	last := byte('.')
	ok := false // ok once we've seen a letter
	partlen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_' || c == '*':
			ok = true
			partlen++
		case '0' <= c && c <= '9':
			// fine
			partlen++
		case c == '-':
			// byte before dash cannot be dot
			if last == '.' {
				return false
			}
			partlen++
		case c == '.':
			// byte before dot cannot be dot, dash
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}

	return ok
}

// Return the number of labels in a domain name.
// Need to add these kind of function in a structured way. TODO(mg)
func Labels(a string) (c uint8) {
	// walk the string and count the dots
	// except when it is escaped
	esc := false
	for _, v := range a {
		switch v {
		case '.':
			if esc {
				esc = !esc
				continue
			}
			c++
		case '\\':
			esc = true
		}
	}
	return
}
