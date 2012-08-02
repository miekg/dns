package main

import (
	"dns"
)

func serve(w dns.ResponseWriter, req *dns.Msg, z *Zones) {
	// for DS go to the parent...? TODO(mg)

	zone := z.Find(req.Question[0].Name)
	if zone == nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		w.Write(m)
		return
	}
	// Need to look how the algorithm is in rfc1035
}
