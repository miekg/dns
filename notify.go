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
