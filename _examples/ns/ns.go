package main

import (
	"os"
	"dns"
	"fmt"
	"flag"
	"json"
)

func main() {
//	var zone *string = flag.String("zone", "", "The zone to serve")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s zone...\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	m := new(dns.Msg)
	m.MsgHdr.Id = dns.Id()
	m.MsgHdr.Authoritative = true
	m.MsgHdr.AuthenticatedData = false
	m.MsgHdr.RecursionAvailable = true
	m.MsgHdr.Response = true
	m.MsgHdr.Opcode = dns.OpcodeQuery
	m.MsgHdr.Rcode = dns.RcodeSuccess
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{"miek.nl.", dns.TypeTXT, dns.ClassINET}
	m.Answer = make([]dns.RR, 1)
	t := new(dns.RR_TXT)
	t.Hdr = dns.RR_Header{Name: "miek.nl.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600}
	t.Txt = "Een antwoord"
	m.Answer[0] = t

	json, err := json.Marshal(m)
	if err != nil {
		fmt.Printf("Err: %s", err.String())
                os.Exit(1)
	}
        fmt.Printf("%v", string(json))

}
