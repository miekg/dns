package dns

import ()

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

// 3.2.4 - Table Of Metavalues Used In Prerequisite Section
//
//   CLASS    TYPE     RDATA    Meaning
//   ------------------------------------------------------------
//   ANY      ANY      empty    Name is in use
//   ANY      rrset    empty    RRset exists (value independent)
//   NONE     ANY      empty    Name is not in use
//   NONE     rrset    empty    RRset does not exist
//   zone     rrset    rr       RRset exists (value dependent)

// PrereqNameUsed sets the RRs in the prereq section to
// "Name is in use" RRs. RFC 2136 section 2.4.4.
func (u *Update) PrereqNameUsed(rr []RR) {
	u.Msg.Answer = make([]RR, len(rr))
	for i, r := range rr {
		u.Msg.Answer[i] = &RR_ANY{Hdr: RR_Header{Name: r.Header().Name, Ttl: 0, Rrtype: TypeANY, Class: ClassANY}}
	}
}

// PrereqNameNotUsed sets the RRs in the prereq section to
// "Name is in not use" RRs. RFC 2136 section 2.4.5.
func (u *Update) PrereqNameNotUsed(rr []RR) {
	u.Msg.Answer = make([]RR, len(rr))
	for i, r := range rr {
                u.Msg.Answer[i] = &RR_ANY{Hdr: RR_Header{Name: r.Header().Name, Ttl: 0, Rrtype: TypeANY, Class: ClassNONE}}
	}
}

// PrereqRRsetUsedFull sets the RRs in the prereq section to
// "RRset exists (value dependent -- with rdata)" RRs. RFC 2136 section 2.4.2.
func (u *Update) PrereqRRsetUsedFull(rr []RR) {
	u.Msg.Answer = make([]RR, len(rr))
	for i, r := range rr {
                u.Msg.Answer[i] = r
                u.Msg.Answer[i].Header().Class = u.Msg.Question[0].Qclass       // TODO crashes if question is zero
	}
}

// PrereqRRsetUsed sets the RRs in the prereq section to
// "RRset exists (value independent -- no rdata)" RRs. RFC 2136 section 2.4.1.
func (u *Update) PrereqRRsetUsed(rr []RR) {
	u.Msg.Answer = make([]RR, len(rr))
	for i, r := range rr {
                u.Msg.Answer[i] = r
                u.Msg.Answer[i].Header().Class = ClassANY
                /* rdata should be cleared */
	}
}

// PrereqRRsetNotUsed sets the RRs in the prereq section to
// "RRset does not exist" RRs. RFC 2136 section 2.4.3.
func (u *Update) PrereqRRsetNotUsed(rr []RR) {
	u.Msg.Answer = make([]RR, len(rr))
	for i, r := range rr {
                u.Msg.Answer[i] = r
                u.Msg.Answer[i].Header().Class = ClassNONE
                /* rdata should be cleared */
	}
}



