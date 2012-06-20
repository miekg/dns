package dns

// This file is in flux

import (
	"math/rand"
	"strings"
	"time"
)

type SecurityStatus int

const (
	SECURE SecurityStatus = iota
	INSECURE
	BOGUS
	INDETERMINATE
)

// Check if the returned message has a delegation signer record
// Algo:
// The auth section's owner name (should be all equal)  - seperate check!
// The ownername of the DS records must match the right side of the qname
// 
func AssertDelegationSigner(m *Msg, trustdb []*RR_DNSKEY) error {

	// look for the DS(s)
	dss := make([]*RR_DS, 0)
	// If there are ddssen, there should also be a SIG (what if not?)
	var sig *RR_RRSIG
	for _, r := range m.Ns {
		if d, ok := r.(*RR_DS); ok {
			dss = append(dss, d)
			continue
		}
		if s, ok := r.(*RR_RRSIG); ok {
			if s.TypeCovered == TypeDS {
				sig = s
			}
		}
	}
	if len(dss) == 0 {
		// No DSs found ... 
		return nil
	}
	println("DSs found", len(dss))
	if sig == nil {
		// No SIG found ...
		return nil
	}
	println("SIG found")

	// Ownername of the DSs should match the qname
	if CompareLabels(dss[0].Header().Name, m.Question[0].Name) == 0 {
		// No match
	}
	// Optionally keep track of these comparison, it should increase
	println("Match found between delegation DS and qname")
	println(dss[0].String())
	println(sig.String())

	return nil

}

// Types of answers (without looking the RFCs)
// len(m.Ns) > 0
// NS records in there? -> delegation (rcode should be rcode.Success)
//	- secure delegation -> DS should be there
//	- insecure delegation -> Proof of no DS (either NSEC or NSEC3)
//	- plain old DNS delegation -> ...
// SOA record in there? -> nxdomain   (rcode should be rcode.Nxdomain)

// Lookup does a (secure) DNS lookup. The message m contains
// the question to be asked. Lookup returns last packet seen
// which is either the answer or a packet somewhere in the
// tree where the error occured.
// TODO: check return code - see unbound for what we want
// 
func Lookup(m *Msg) (*Msg, error) {

	// This is actually what needs to be done when parsing packets too
	a, aaaa := primingZone()
	ds := primingTrust()
	for i, r := range a {
		println(i, r)
	}
	for i, r := range aaaa {
		println(i, r)
	}
	for i, r := range ds {
		println(i, r.String())
	}
	c := new(Client)
	a1 := randomAddress(a)
	println(a1)
	n, _, _, e := c.ExchangeRtt(m, a1+":53")
	if e == nil {
		println(n.String())
	} else {
		println(e.Error())
		return nil, e
	}
	// n is our reply, deal with it
	// Check for DS
	// Check for DS absent (NSEC/NSEC3)
	if len(n.Ns) > 0 && len(n.Answer) == 0 && n.Rcode == RcodeSuccess { // Referral
		// the ns name of the nameservers should match the right most labels. Check the answer 
		println("Referral")
		for i, j := range addrFromReferral4(n) {
			println(i, j)
		}
	}
	return nil, nil
}

// Parse a referral packet and return two lists (v4 and v6) of
// ip addresses to try next. As the NS records in a referral
// are not signed (the belong to the child), no validation takes
// place at this step.
func parseReferral(m *Msg) ([]*RR_A, []*RR_AAAA) {
	return nil, nil
}

// Parse the builtin root zone and return two lists (v4 and v6) of
// ip addresses to try.
// Glue checking this is -- should be done much nicer/better
func primingZone() (a, aaaa []string) {
	nss := make(map[string]bool) // List of ns names
	// Walk the records, get each NS for . and look for the addresses
	for rr := range ParseZone(strings.NewReader(NamedRoot), "", "named.root") {
		if rr.RR.Header().Name == "." && rr.RR.Header().Rrtype == TypeNS {
			nss[rr.RR.(*RR_NS).Ns] = true
			continue
		}
		if rr.RR.Header().Rrtype == TypeA {
			for n, _ := range nss {
				if rr.RR.Header().Name == n {
					a = append(a, rr.RR.(*RR_A).A.String())
				}
			}
			continue
		}
		if rr.RR.Header().Rrtype == TypeAAAA {
			for n, _ := range nss {
				if rr.RR.Header().Name == n {
					aaaa = append(aaaa, rr.RR.(*RR_AAAA).AAAA.String())
				}
			}
		}
	}
	// Randomize
	return
}

// Validate the root key with the DS records we've gotten offline
func createTrustDB(dss []*RR_DS, a, aaaa []string) *[]RR_DNSKEY {
	// Query a root server, get the DNSKEY, toDS() and check
	return nil

}

// Parse the builtin trust anchor and return the DS records
func primingTrust() []*RR_DS {
	ta, _ := ReadTrustAnchor(strings.NewReader(RootAnchorXML))
	// Don't care about validity just yet
	dss := make([]*RR_DS, 0)
	for _, t := range ta {
		dss = append(dss, t.Anchor)
	}
	return dss
}

func randomAddress(list []string) string {
	rand.Seed(int64(time.Now().Nanosecond()))
	if len(list) == 0 {
		return ""
	}
	return list[rand.Intn(len(list))]
}

// Pull the addresses out of the referral message
// Check the zone
func addrFromReferral4(m *Msg) (addr []string) {
	for _, ns := range m.Ns {
		if ns.Header().Rrtype != TypeNS {
			continue
		}
		for _, a := range m.Extra {
			if a.Header().Rrtype != TypeA {
				continue
			}
			if ns.(*RR_NS).Ns == a.Header().Name {
				addr = append(addr, a.(*RR_A).A.String())
			}
		}
	}
	return
}
