package dns

// Implements wrapper functions for dealing with dynamic update packets.
// Dynamic update packets are identical to normal DNS messages, but the
// names are redefined. See RFC 2136 for the details.

type Update struct{ Msg }

// Not sure if I want to keep these functions, but they
// may help a programmer

func (u *Update) Zone() []Question {
	return u.Msg.Question
}

func (u *Update) Prereq() []RR {
	return u.Msg.Answer
}

func (u *Update) Update() []RR {
	return u.Msg.Ns
}

func (u *Update) Additional() []RR {
	return u.Msg.Extra
}

// NewUpdate creats a new DNS update packet.
func NewUpdate(zone string, class uint16) *Update {
	u := new(Update)
	u.MsgHdr.Opcode = OpcodeUpdate
	u.Question = make([]Question, 1)
	u.Question[0] = Question{zone, TypeSOA, class}
	return u
}

// 3.2.4 - Table Of Metavalues Used In Prerequisite Section
//
//   CLASS    TYPE     RDATA    Meaning
//   ------------------------------------------------------------
//   ANY      ANY      empty    Name is in use
//   ANY      rrset    empty    RRset exists (value independent)
//   NONE     ANY      empty    Name is not in use
//   NONE     rrset    empty    RRset does not exist
//   zone     rrset    rr       RRset exists (value dependent)

// NameUsed sets the RRs in the prereq section to
// "Name is in use" RRs. RFC 2136 section 2.4.4.
func (u *Update) NameUsed(rr []RR) {
	u.Answer = make([]RR, len(rr))
	for i, r := range rr {
		u.Answer[i] = &RR_ANY{Hdr: RR_Header{Name: r.Header().Name, Ttl: 0, Rrtype: TypeANY, Class: ClassANY}}
	}
}

// NameNotUsed sets the RRs in the prereq section to
// "Name is in not use" RRs. RFC 2136 section 2.4.5.
func (u *Update) NameNotUsed(rr []RR) {
	u.Answer = make([]RR, len(rr))
	for i, r := range rr {
		u.Answer[i] = &RR_ANY{Hdr: RR_Header{Name: r.Header().Name, Ttl: 0, Rrtype: TypeANY, Class: ClassNONE}}
	}
}

// RRsetUsedFull sets the RRs in the prereq section to
// "RRset exists (value dependent -- with rdata)" RRs. RFC 2136 section 2.4.2.
func (u *Update) RRsetUsedFull(rr []RR) {
	if len(u.Msg.Question) == 0 {
		panic("empty question section")
	}
	u.Answer = make([]RR, len(rr))
	for i, r := range rr {
		u.Answer[i] = r
		u.Answer[i].Header().Class = u.Msg.Question[0].Qclass
	}
}

// RRsetUsed sets the RRs in the prereq section to
// "RRset exists (value independent -- no rdata)" RRs. RFC 2136 section 2.4.1.
func (u *Update) RRsetUsed(rr []RR) {
	u.Answer = make([]RR, len(rr))
	for i, r := range rr {
		u.Answer[i] = r
		u.Answer[i].Header().Class = ClassANY
		u.Answer[i].Header().Ttl = 0
		u.Answer[i].Header().Rdlength = 0
	}
}

// RRsetNotUsed sets the RRs in the prereq section to
// "RRset does not exist" RRs. RFC 2136 section 2.4.3.
func (u *Update) RRsetNotUsed(rr []RR) {
	u.Answer = make([]RR, len(rr))
	for i, r := range rr {
		u.Answer[i] = r
		u.Answer[i].Header().Class = ClassNONE
		u.Answer[i].Header().Rdlength = 0
		u.Answer[i].Header().Ttl = 0
	}
}

// 3.4.2.6 - Table Of Metavalues Used In Update Section
//
//   CLASS    TYPE     RDATA    Meaning
//   ---------------------------------------------------------
//   ANY      ANY      empty    Delete all RRsets from a name
//   ANY      rrset    empty    Delete an RRset
//   NONE     rrset    rr       Delete an RR from an RRset
//   zone     rrset    rr       Add to an RRset

// RRsetAddFull adds an complete RRset, see RFC 2136 section 2.5.1
func (u *Update) RRsetAddFull(rr []RR) {
	if len(u.Msg.Question) == 0 {
		panic("empty question section")
	}
	u.Ns = make([]RR, len(rr))
	for i, r := range rr {
		u.Ns[i] = r
		u.Ns[i].Header().Class = u.Msg.Question[0].Qclass
	}
}

// RRsetDelete delete an RRset, see RFC 2136 section 2.5.2
func (u *Update) RRsetDelete(rr []RR) {
	u.Ns = make([]RR, len(rr))
	for i, r := range rr {
		u.Ns[i] = r
		u.Ns[i].Header().Class = ClassANY
		u.Ns[i].Header().Rdlength = 0
		u.Ns[i].Header().Ttl = 0
	}
}

// NameDelete deletes all RRsets of a name, see RFC 2136 section 2.5.3
func (u *Update) NameDelete(rr []RR) {
	u.Ns = make([]RR, len(rr))
	for i, r := range rr {
		u.Ns[i] = &RR_ANY{Hdr: RR_Header{Name: r.Header().Name, Ttl: 0, Rrtype: TypeANY, Class: ClassANY}}
	}
}

// RRsetDeleteRR deletes RR from the RRSset, see RFC 2136 section 2.5.4
func (u *Update) RRsetDeleteRR(rr []RR) {
	u.Ns = make([]RR, len(rr))
	for i, r := range rr {
		u.Ns[i] = r
		u.Ns[i].Header().Class = ClassNONE
	}
}
