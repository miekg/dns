package dns

import (
	"math/rand"
	"strings"
	"time"
)

// Nxdomain, Secure, Bogus

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
	if len(n.Ns) > 0 && len(n.Answer) == 0  && n.Rcode == RcodeSuccess {	// Referral
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
