package main

import (
	"dns"
	"log"
)

func serve(w dns.ResponseWriter, req *dns.Msg, z *dns.Zone) {
	log.Printf("incoming %s %s\n", req.Question[0].Name, dns.Rr_str[req.Question[0].Qtype])
	// Check for referral
	// if we find something with NonAuth = true, it means
	// we need to return referral
	nss := z.Predecessor(req.Question[0].Name)
	if nss != nil && nss.NonAuth {
		log.Printf("Referral")
		m := new(dns.Msg)
		m.SetReply(req)
		m.Ns = nss.RR[dns.TypeNS]
		// lookup the a records for additional, only when
		// in baliwick
		w.Write(m)
		return

	}

	// If we don't have the name return NXDOMAIN
	node := z.Find(req.Question[0].Name)
	if node == nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		w.Write(m)
		return
	}
	apex := z.Find(z.Origin)

	// Check if we have the type
	if rrs, ok := node.RR[req.Question[0].Qtype]; ok {
		m := new(dns.Msg)
		m.SetReply(req)
		m.MsgHdr.Authoritative = true
		m.Answer = rrs
		m.Ns = apex.RR[dns.TypeNS] // Add auth section
		w.Write(m)
		return
	} else {
		// We don't have the type, check if we have non-auth ns servers, if so
		// we need to return a referral
		if nss, ok := node.RR[dns.TypeNS]; ok && node.NonAuth {
			log.Printf("Also Referral!!")
			m := new(dns.Msg)
			m.SetReply(req)
			m.Ns = nss
			// lookup the a records for additional, only when
			// in baliwick
			w.Write(m)

		}
		m := new(dns.Msg) // Nodata reply
		m.SetReply(req)
		m.Ns = apex.RR[dns.TypeSOA]
		w.Write(m)
		return
	}
	// See RFC 1035...
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeNameError)

	w.Write(m)
}
