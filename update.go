// DYNAMIC UPDATES
// 
// Dynamic updates reuses the DNS message format, but renames the three of
// the sections. Question is Zone, Answer is Prerequisite, Authority is
// Update, only the Additional is not renamed. See RFC 2136 for the gory details.
//
// You can set a rather complex set of rules for the existence of absence of
// certain resource records or names in a zone to specify if resource records
// should be added or removed. The table from RFC 2136 supplemented with the Go 
// DNS function shows which functions exist to specify the prerequisites.
//
// 3.2.4 - Table Of Metavalues Used In Prerequisite Section
//
//   CLASS    TYPE     RDATA    Meaning                          Function
//   ----------------------------------------------------------------------------
//   ANY      ANY      empty    Name is in use                   NameUsed
//   ANY      rrset    empty    RRset exists (value independent) RRsetUsedNoRdata
//   NONE     ANY      empty    Name is not in use               NameNotUsed
//   NONE     rrset    empty    RRset does not exist             RRsetNotUsed
//   zone     rrset    rr       RRset exists (value dependent)   RRsetUsedRdata
// 
// The prerequisite section can also be left empty.
// If you have decided an the prerequisites you can tell what RRs should
// be added or deleted. The next table shows the options you have and
// what function to call.
// 3.4.2.6 - Table Of Metavalues Used In Update Section
// 
//   CLASS    TYPE     RDATA    Meaning                          Function
//   -------------------------------------------------------------------------
//   ANY      ANY      empty    Delete all RRsets from a name    NameDelete
//   ANY      rrset    empty    Delete an RRset                  RRsetDelete
//   NONE     rrset    rr       Delete an RR from an RRset       RRsetDeleteRR
//   zone     rrset    rr       Add to an RRset                  RRsetAddRdata
// 
package dns

// NewUpdate creates a new DNS update packet, which is a normal DNS message.
func NewUpdate(zone string, class uint16) *Msg {
	u := new(Msg)
	u.MsgHdr.Response = false
	u.MsgHdr.Opcode = OpcodeUpdate
	u.Compress = false // Seems BIND9 at least cannot handle compressed update pkgs
	u.Question = make([]Question, 1)
	u.Question[0] = Question{zone, TypeSOA, class}
	return u
}

// The table from RFC 2136 supplemented with the Go DNS function.
//
// 3.2.4 - Table Of Metavalues Used In Prerequisite Section
//
//   CLASS    TYPE     RDATA    Meaning                           Function
//   ----------------------------------------------------------------------
//   ANY      ANY      empty    Name is in use                    NameUsed
//   ANY      rrset    empty    RRset exists (value independent)  RRsetUsedNoRdata
//   NONE     ANY      empty    Name is not in use                NameNotUsed
//   NONE     rrset    empty    RRset does not exist              RRsetNotUsed
//   zone     rrset    rr       RRset exists (value dependent)    RRsetUsedRdata

// NameUsed sets the RRs in the prereq section to
// "Name is in use" RRs. RFC 2136 section 2.4.4.
func (u *Msg) NameUsed(rr []RR) {
	u.Answer = make([]RR, len(rr))
	for i, r := range rr {
		u.Answer[i] = &RR_ANY{Hdr: RR_Header{Name: r.Header().Name, Ttl: 0, Rrtype: TypeANY, Class: ClassANY}}
	}
}

// NameNotUsed sets the RRs in the prereq section to
// "Name is in not use" RRs. RFC 2136 section 2.4.5.
func (u *Msg) NameNotUsed(rr []RR) {
	u.Answer = make([]RR, len(rr))
	for i, r := range rr {
		u.Answer[i] = &RR_ANY{Hdr: RR_Header{Name: r.Header().Name, Ttl: 0, Rrtype: TypeANY, Class: ClassNONE}}
	}
}

// RRsetUsedRdata sets the RRs in the prereq section to
// "RRset exists (value dependent -- with rdata)" RRs. RFC 2136 section 2.4.2.
func (u *Msg) RRsetUsedRdata(rr []RR) {
	if len(u.Question) == 0 {
		panic("empty question section")
	}
	u.Answer = make([]RR, len(rr))
	for i, r := range rr {
		u.Answer[i] = r
		u.Answer[i].Header().Class = u.Question[0].Qclass
	}
}

// RRsetUsedNoRdata sets the RRs in the prereq section to
// "RRset exists (value independent -- no rdata)" RRs. RFC 2136 section 2.4.1.
func (u *Msg) RRsetUsedNoRdata(rr []RR) {
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
func (u *Msg) RRsetNotUsed(rr []RR) {
	u.Answer = make([]RR, len(rr))
	for i, r := range rr {
		u.Answer[i] = r
		u.Answer[i].Header().Class = ClassNONE
		u.Answer[i].Header().Rdlength = 0
		u.Answer[i].Header().Ttl = 0
	}
}

// The table from RFC 2136 supplemented with the Go DNS function.
//
// 3.4.2.6 - Table Of Metavalues Used In Update Section
//
//   CLASS    TYPE     RDATA    Meaning                         Function
//   --------------------------------------------------------------------------
//   ANY      ANY      empty    Delete all RRsets from a name   NameDelete
//   ANY      rrset    empty    Delete an RRset                 RRsetDelete
//   NONE     rrset    rr       Delete an RR from an RRset      RRsetDeleteRR
//   zone     rrset    rr       Add to an RRset                 RRsetAddRdata

// RRsetAddRdata adds an complete RRset, see RFC 2136 section 2.5.1
func (u *Msg) RRsetAddRdata(rr []RR) {
	if len(u.Question) == 0 {
		panic("empty question section")
	}
	u.Ns = make([]RR, len(rr))
	for i, r := range rr {
		u.Ns[i] = r
		u.Ns[i].Header().Class = u.Question[0].Qclass
	}
}

// RRsetDelete deletes an RRset, see RFC 2136 section 2.5.2
func (u *Msg) RRsetDelete(rr []RR) {
	u.Ns = make([]RR, len(rr))
	for i, r := range rr {
		u.Ns[i] = r
		u.Ns[i].Header().Class = ClassANY
		u.Ns[i].Header().Rdlength = 0
		u.Ns[i].Header().Ttl = 0
	}
}

// NameDelete deletes all RRsets of a name, see RFC 2136 section 2.5.3
func (u *Msg) NameDelete(rr []RR) {
	u.Ns = make([]RR, len(rr))
	for i, r := range rr {
		u.Ns[i] = &RR_ANY{Hdr: RR_Header{Name: r.Header().Name, Ttl: 0, Rrtype: TypeANY, Class: ClassANY}}
	}
}

// RRsetDeleteRR deletes RR from the RRSset, see RFC 2136 section 2.5.4
func (u *Msg) RRsetDeleteRR(rr []RR) {
	u.Ns = make([]RR, len(rr))
	for i, r := range rr {
		u.Ns[i] = r
		u.Ns[i].Header().Class = ClassNONE
		u.Ns[i].Header().Ttl = 0
	}
}
