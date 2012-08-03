package main

import (
	"dns"
	"log"
)

func serve(w dns.ResponseWriter, req *dns.Msg, z *dns.Zone) {
	// See RFC 1035...

	log.Printf("incoming %s\n", req.Question[0].Name)
	// dynamic updates
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeNameError)

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
	w.Write(m)
}
