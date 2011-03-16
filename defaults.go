package dns

// Create a notify request packet.
func (dns *Msg) SetNotifyRequest(z string, class uint16) {
	dns.MsgHdr.Opcode = OpcodeNotify
	dns.MsgHdr.Authoritative = true
	dns.MsgHdr.Id = Id()
	dns.Question = make([]Question, 1)
	dns.Question[0] = Question{z, TypeSOA, class}
}

// Create a notify reply packet.
func (dns *Msg) SetNotifyReply(z string, class, id uint16) {
	dns.MsgHdr.Opcode = OpcodeNotify
	dns.MsgHdr.Authoritative = true
	dns.MsgHdr.Response = true
	dns.MsgHdr.Id = id
	dns.Question = make([]Question, 1)
	dns.Question[0] = Question{z, TypeSOA, class}
}

// Is a dns msg a valid notify packet?
func (dns *Msg) IsNotify() bool {
	ok := dns.MsgHdr.Opcode == OpcodeNotify
	if len(dns.Question) == 0 {
		ok = false
	}
	ok = ok && dns.Question[0].Qclass == ClassINET
	ok = ok && dns.Question[0].Qtype == TypeSOA
	return ok
}

func (dns *Msg) SetIxfrRequest(z string, class uint16, serial uint32) {
	dns.Question = make([]Question, 1)
	dns.Ns = make([]RR, 1)
	s := new(RR_SOA)
	s.Hdr = RR_Header{z, TypeSOA, class, DefaultTtl, 0}
	s.Serial = serial

	dns.Question[0] = Question{z, TypeIXFR, class}
        dns.Ns[0] = s
}

func (dns *Msg) SetAxfrRequest(z string, class uint16) {
	dns.Question = make([]Question, 1)
	dns.Question[0] = Question{z, TypeAXFR, class}
}

// IsIxfr/IsAxfr?
