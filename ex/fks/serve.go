package main

import (
	"dns"
	"log"
)

func serve(w dns.ResponseWriter, req *dns.Msg, z *dns.Zone) {
	// See RFC 1035...
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)

	log.Printf("incoming %s\n", req.Question[0].Name)
	// For now:
	// look up name -> yes, continue, no -> nxdomain
	node := z.Find(req.Question[0].Name)
	if node == nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		w.Write(m)
		return
	}
	apex := z.Find(z.Origin)
	// Referral need support from the radix tree, successor?
	// Name found, look for type, yes, answer, no 
	if rrs, ok := node.RR[req.Question[0].Qtype]; ok {
		// Need to look at class to but... no
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = rrs
		// auth section
		m.Ns = apex.RR[dns.TypeNS]
		w.Write(m)
		return
	} else {
		// nodate reply
		// soa in auth section
		m := new(dns.Msg)
		m.SetReply(req)
		m.Ns = apex.RR[dns.TypeSOA]
		w.Write(m)
		return
	}
	w.Write(m)
}
