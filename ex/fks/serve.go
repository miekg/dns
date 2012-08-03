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
		log.Printf("nothing found")
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		w.Write(m)
		return
	}
	// Referral?
	// Name found, look for type, yes, answer, no 
	if rrs, ok := node.RR[req.Question[0].Qtype] {
		// rrs match name and type
		// Need to look at class to but... no
		// create answer
	}



	w.Write(m)
}
