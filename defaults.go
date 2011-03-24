package dns

// Everything is assumed in the ClassINET class

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

// IsReply?

// Create a notify packet.
func (dns *Msg) SetNotify(z string, class uint16) {
	dns.MsgHdr.Opcode = OpcodeNotify
	dns.MsgHdr.Authoritative = true
	dns.MsgHdr.Id = Id()
	dns.Question = make([]Question, 1)
	dns.Question[0] = Question{z, TypeSOA, class}
}

// Is the message a valid notify packet?
func (dns *Msg) IsNotify() (ok bool) {
	if len(dns.Question) == 0 {
		return false
	}
	ok = dns.MsgHdr.Opcode == OpcodeNotify
	ok = ok && dns.Question[0].Qclass == ClassINET
	ok = ok && dns.Question[0].Qtype == TypeSOA
	return ok
}

// Create a dns msg suitable for requesting an ixfr.
func (dns *Msg) SetIxfr(z string, serial uint32) {
	dns.Question = make([]Question, 1)
	dns.Ns = make([]RR, 1)
	s := new(RR_SOA)
	s.Hdr = RR_Header{z, TypeSOA, ClassINET, DefaultTtl, 0}
	s.Serial = serial

	dns.Question[0] = Question{z, TypeIXFR, ClassINET}
	dns.Ns[0] = s
}

// Create a dns msg suitable for requesting an axfr.
func (dns *Msg) SetAxfr(z string) {
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
	return ok
}

// Is the message a valid ixfr request packet?
func (dns *Msg) IsIxfr() (ok bool) {
	if len(dns.Question) == 0 {
		return false
	}
	ok = dns.MsgHdr.Opcode == OpcodeQuery
	ok = ok && dns.Question[0].Qclass == ClassINET
	ok = ok && dns.Question[0].Qtype == TypeIXFR
	return ok
}
