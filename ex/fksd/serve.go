package main

import (
	"dns"
	"strings"
)

// Create skeleton edns opt RR from the query and
// add it to the message m
func ednsFromRequest(req, m *dns.Msg) {
	for _, r := range req.Extra {
		if r.Header().Rrtype == dns.TypeOPT {
			m.SetEdns0(4096, r.(*dns.RR_OPT).Do())
			return
		}
	}
	return
}

func serve(w dns.ResponseWriter, req *dns.Msg, z *dns.Zone) {
	if z == nil {
		panic("fksd: no zone")
	}
	logPrintf("[zone %s] incoming %s %s %d from %s\n", z.Origin, req.Question[0].Name, dns.Rr_str[req.Question[0].Qtype], req.MsgHdr.Id, w.RemoteAddr())
	// if we find something with NonAuth = true, it means we need to return referral
	nss := z.Predecessor(req.Question[0].Name)
	m := new(dns.Msg)
	if nss != nil && nss.NonAuth {
		m.SetReply(req)
		m.Ns = nss.RR[dns.TypeNS]
		for _, n := range m.Ns {
			if dns.IsSubDomain(n.(*dns.RR_NS).Ns, n.Header().Name) {
				// Need glue
				glue := z.Find(n.(*dns.RR_NS).Ns)
				if glue != nil {
					if a4, ok := glue.RR[dns.TypeAAAA]; ok {
						m.Extra = append(m.Extra, a4...)
					}
					if a, ok := glue.RR[dns.TypeA]; ok {
						m.Extra = append(m.Extra, a...)
					}
					// length
				}
			}
		}
		ednsFromRequest(req, m)
		w.Write(m)
		return
	}

	// If we don't have the name return NXDOMAIN
	node := z.Find(req.Question[0].Name)
	if node == nil {
		if z.Wildcard > 0 {
			lx := dns.SplitLabels(req.Question[0].Name)
			wc := "*." + strings.Join(lx[1:], ".")
			node = z.Find(wc)
			if node != nil {
				goto Wildcard
			}
		}
		m.SetRcode(req, dns.RcodeNameError)
		ednsFromRequest(req, m)
		w.Write(m)
		return
	}

	Wildcard:

	// We have the name it isn't a referral, but it may that
	// we still have NSs for this name. If we have nss and they
	// are NonAuth true return those.
	if nss, ok := node.RR[dns.TypeNS]; ok && node.NonAuth {
		m.SetReply(req)
		m.Ns = nss
		for _, n := range m.Ns {
			if dns.IsSubDomain(n.(*dns.RR_NS).Ns, n.Header().Name) {
				// Need glue
				glue := z.Find(n.(*dns.RR_NS).Ns)
				if glue != nil {
					if a4, ok := glue.RR[dns.TypeAAAA]; ok {
						m.Extra = append(m.Extra, a4...)
					}
					if a, ok := glue.RR[dns.TypeA]; ok {
						m.Extra = append(m.Extra, a...)
					}
					// length
				}
			}
		}
		ednsFromRequest(req, m)
		w.Write(m)
		return
	}

	apex := z.Find(z.Origin)

	if rrs, ok := node.RR[req.Question[0].Qtype]; ok {
		m.SetReply(req)
		m.MsgHdr.Authoritative = true
		m.Answer = rrs
		m.Ns = apex.RR[dns.TypeNS]
		ednsFromRequest(req, m)
		w.Write(m)
		return
	} else { // NoData reply or CNAME
		m.SetReply(req)
		if cname, ok := node.RR[dns.TypeCNAME]; ok {
			m.Answer = cname // tODO
		}
		m.Ns = apex.RR[dns.TypeSOA]
		ednsFromRequest(req, m)
		w.Write(m)
		return
	}
	m.SetRcode(req, dns.RcodeNameError)
	ednsFromRequest(req, m)
	w.Write(m)
}
