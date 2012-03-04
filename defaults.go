package dns

// Everything is assumed in the ClassINET class. If
// you need other classes you are on your own.

// SetReply creates a reply packet from a request message.
func (dns *Msg) SetReply(request *Msg) {
	dns.MsgHdr.Id = request.MsgHdr.Id
	dns.MsgHdr.Authoritative = true
	dns.MsgHdr.Response = true
	dns.MsgHdr.Opcode = OpcodeQuery
	dns.MsgHdr.Rcode = RcodeSuccess
	dns.Question = make([]Question, 1)
	dns.Question[0] = request.Question[0]
}

// SetQuestion creates a question packet.
func (dns *Msg) SetQuestion(z string, t uint16) {
	dns.MsgHdr.Id = Id()
	dns.MsgHdr.RecursionDesired = true
	dns.Question = make([]Question, 1)
	dns.Question[0] = Question{z, t, ClassINET}
}

// SetNotify creates a notify packet.
func (dns *Msg) SetNotify(z string) {
	dns.MsgHdr.Opcode = OpcodeNotify
	dns.MsgHdr.Authoritative = true
	dns.MsgHdr.Id = Id()
	dns.Question = make([]Question, 1)
	dns.Question[0] = Question{z, TypeSOA, ClassINET}
}

// SetRcode creates an error packet.
func (dns *Msg) SetRcode(request *Msg, rcode int) {
	dns.MsgHdr.Rcode = rcode
	dns.MsgHdr.Opcode = OpcodeQuery
	dns.MsgHdr.Response = true
	dns.MsgHdr.Authoritative = false
	dns.MsgHdr.Id = request.MsgHdr.Id
	dns.Question = make([]Question, 1)
	dns.Question[0] = request.Question[0]
}

// SetRcodeFormatError creates a packet with FormError set.
func (dns *Msg) SetRcodeFormatError(request *Msg) {
	dns.MsgHdr.Rcode = RcodeFormatError
	dns.MsgHdr.Opcode = OpcodeQuery
	dns.MsgHdr.Response = true
	dns.MsgHdr.Authoritative = false
	dns.MsgHdr.Id = request.MsgHdr.Id
}

// SetUpdate makes the message a dynamic update packet. It
// sets the ZONE section to: z, TypeSOA, classINET.
func (dns *Msg) SetUpdate(z string) {
	dns.MsgHdr.Id = Id()
	dns.MsgHdr.Opcode = OpcodeUpdate
	dns.Question = make([]Question, 1)
	dns.Question[0] = Question{z, TypeSOA, ClassINET}
}

// SetIxfr creates dns msg suitable for requesting an ixfr.
func (dns *Msg) SetIxfr(z string, serial uint32) {
	dns.MsgHdr.Id = Id()
	dns.Question = make([]Question, 1)
	dns.Ns = make([]RR, 1)
	s := new(RR_SOA)
	s.Hdr = RR_Header{z, TypeSOA, ClassINET, DefaultTtl, 0}
	s.Serial = serial

	dns.Question[0] = Question{z, TypeIXFR, ClassINET}
	dns.Ns[0] = s
}

// SetAxfr creates dns msg suitable for requesting an axfr.
func (dns *Msg) SetAxfr(z string) {
	dns.MsgHdr.Id = Id()
	dns.Question = make([]Question, 1)
	dns.Question[0] = Question{z, TypeAXFR, ClassINET}
}

// SetTsig appends a TSIG RR to the message.
// This is only a skeleton Tsig RR that is added as the last RR in the 
// additional section. The Tsig is calculated when the message is being
// send.
func (dns *Msg) SetTsig(z, algo string, fudge, origid uint16, timesigned int64) {
	t := new(RR_TSIG)
	t.Hdr = RR_Header{z, TypeTSIG, ClassANY, 0, 0}
	t.Algorithm = algo
	t.Fudge = 300
	t.TimeSigned = uint64(timesigned)
	t.OrigId = origid
	dns.Extra = append(dns.Extra, t)
}

// SetEdns0 appends a EDNS0 OPT RR to the message. 
// TSIG should always the last RR in a message.
func (dns *Msg) SetEdns0(udpsize uint16, do bool) {
	e := new(RR_OPT)
	e.Hdr.Name = "."
	e.Hdr.Rrtype = TypeOPT
	e.SetUDPSize(udpsize)
	if do {
		e.SetDo()
	}
	dns.Extra = append(dns.Extra, e)
}

// IsRcode checks if the header of the packet has rcode set.
func (dns *Msg) IsRcode(rcode int) (ok bool) {
	if len(dns.Question) == 0 {
		return false
	}
	ok = dns.MsgHdr.Rcode == rcode
	return
}

// IsQuestion returns true if the packet is a question.
func (dns *Msg) IsQuestion() (ok bool) {
	if len(dns.Question) == 0 {
		return false
	}
	ok = dns.MsgHdr.Response == false
	return
}

// IsRcodeFormatError checks if the message has FormErr set.
func (dns *Msg) IsRcodeFormatError() (ok bool) {
	if len(dns.Question) == 0 {
		return false
	}
	ok = dns.MsgHdr.Rcode == RcodeFormatError
	return
}

// IsUpdate checks if the message is a dynamic update packet.
func (dns *Msg) IsUpdate() (ok bool) {
	if len(dns.Question) == 0 {
		return false
	}
	ok = dns.MsgHdr.Opcode == OpcodeUpdate
	ok = ok && dns.Question[0].Qtype == TypeSOA
	return
}

// IsNotify checks if the message is a valid notify packet.
func (dns *Msg) IsNotify() (ok bool) {
	if len(dns.Question) == 0 {
		return false
	}
	ok = dns.MsgHdr.Opcode == OpcodeNotify
	ok = ok && dns.Question[0].Qclass == ClassINET
	ok = ok && dns.Question[0].Qtype == TypeSOA
	return
}

// IsAxfr checks if the message is a valid axfr request packet.
func (dns *Msg) IsAxfr() (ok bool) {
	if len(dns.Question) == 0 {
		return false
	}
	ok = dns.MsgHdr.Opcode == OpcodeQuery
	ok = ok && dns.Question[0].Qclass == ClassINET
	ok = ok && dns.Question[0].Qtype == TypeAXFR
	return
}

// IsIXfr checks if the message is a valid ixfr request packet.
func (dns *Msg) IsIxfr() (ok bool) {
	if len(dns.Question) == 0 {
		return false
	}
	ok = dns.MsgHdr.Opcode == OpcodeQuery
	ok = ok && dns.Question[0].Qclass == ClassINET
	ok = ok && dns.Question[0].Qtype == TypeIXFR
	return
}

// IsTsig checks if the message has a TSIG record as the last record
// in the additional section.
func (dns *Msg) IsTsig() (ok bool) {
	if len(dns.Extra) > 0 {
		return dns.Extra[len(dns.Extra)-1].Header().Rrtype == TypeTSIG
	}
	return
}

// IsEdns0 checks if the message has a Edns0 record, any EDNS0
// record in the additional section will do.
func (dns *Msg) IsEdns0() (ok bool) {
	for _, r := range dns.Extra {
		if r.Header().Rrtype == TypeOPT {
			return true
		}
	}
	return
}

// IsDomainName checks if s is a valid domainname, it returns
// the number of labels, total length and true, when a domain name is valid. 
// When false is returned the labelcount and length are not defined.
func IsDomainName(s string) (uint8, uint8, bool) { // copied from net package.
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
	for i := 0; i < l; i++ {
		c := s[i]
		switch {
		default:
			return 0, uint8(l - longer), false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_' || c == '*':
			ok = true
			partlen++
		case c == '\\':
			// Ok
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
	// If the number of labels both domain name have
	// in common equals the number of labels of parent,
	// child is a subdomain of parent.
	plabs := SplitLabels(parent)
	clabs := SplitLabels(child)
	if len(clabs) < len(plabs) {
		// child is smaller than parent, reversed arguments?
		return false
	}
	// Copied from CompareLabels to prevent another SplitLabels
	n := 0
	p := len(plabs) - 1
	c := len(clabs) - 1
	for {
		if p < 0 || c < 0 {
			break
		}
		if plabs[p] == clabs[c] {
			n++
		} else {
			break
		}
		p--
		c--
	}
	return n == len(plabs)
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
