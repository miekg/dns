package main

import (
	"bufio"
	"dns"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"
	"strings"
)

// A small nameserver implementation, not too fast.
var (
	zone     *dns.Zone
	ns       []dns.RR
	nsDNSSEC []dns.RR
	soa      dns.RR
	spamIN   dns.RR
	spamCH   dns.RR
	debug    *bool
)

func send(w dns.ResponseWriter, m *dns.Msg) {
	buf, _ := m.Pack()
	w.Write(buf)
}

func handleQueryCHAOS(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	qname := strings.ToLower(req.Question[0].Name)
	qtype := req.Question[0].Qtype
	qclass := req.Question[0].Qclass

	m.Extra = make([]dns.RR, 1)
	m.Extra[0] = spamCH

	if qclass != dns.ClassCHAOS {
		m.SetRcode(req, dns.RcodeServerFailure)
		send(w, m)
		return
	}

	if (qname == "version.bind." || qname == "id.server.") && qtype == dns.TypeTXT {
		m.SetReply(req)
		m.Answer = make([]dns.RR, 1)
		m.Answer[0] = &dns.RR_TXT{Hdr: dns.RR_Header{Name: qname,
			Rrtype: qtype, Class: qclass}, Txt: "NS 0.0.1"}
		send(w, m)
		return
	}
	if (qname == "authors.bind." || qname == "authors.server.") && qtype == dns.TypeTXT {
		m.SetReply(req)
		m.Answer = make([]dns.RR, 1)
		m.Answer[0] = &dns.RR_TXT{Hdr: dns.RR_Header{Name: qname,
			Rrtype: qtype, Class: qclass}, Txt: "Miek Gieben"}
		send(w, m)
		return
	}
	m.SetRcode(req, dns.RcodeServerFailure)
	send(w, m)
	return
}

func handleQuery(w dns.ResponseWriter, req *dns.Msg) {
	var dnssec bool
	m := new(dns.Msg)
	if req.Question[0].Qclass != dns.ClassINET {
		m.SetRcode(req, dns.RcodeServerFailure)
		send(w, m)
		return
	}
	m.SetReply(req)
	m.Ns = ns
	m.Extra = make([]dns.RR, 1)
	m.Extra[0] = spamIN

	// Check DNSSEC OK
	for _, v := range req.Extra {
		if o, ok := v.(*dns.RR_OPT); ok {
			if dnssec = o.Do(); dnssec {
				m.Extra = append(m.Extra, o)
				m.Ns = nsDNSSEC
				break
			}
		}
	}

	//m.Answer = make([]dns.RR, 0)
	s, _ := zone.LookupQuestion(req.Question[0])
	if s == nil {
		// Authority section should only contain the SOA record for NXDOMAIN
		m.Ns = m.Ns[:1]
		m.Ns[0] = soa
		m.MsgHdr.Rcode = dns.RcodeNameError
		send(w, m)
		// Lookup the previous name in the Nxt list for this zone
		// and insert the nsec/nsec3 from that. Also give the nsec
		// that proofs there is no wildcard
		return
	}

	// TODO CNAME
	//cname:
	switch req.Question[0].Qtype {
	case dns.TypeRRSIG:
		m.Answer = s.RRsigs
	case dns.TypeNSEC, dns.TypeNSEC3:
		m.Answer = []dns.RR{s.Nxt}
	default:
		m.Answer = s.RRs
	}
	if dnssec && req.Question[0].Qtype != dns.TypeRRSIG && len(s.RRsigs) > 0 {
		for _, r := range s.RRsigs {
			m.Answer = append(m.Answer, r)
		}
	}
	if *debug {
		println(m.Question[0].String())
	}
	send(w, m)
}

func main() {
	debug = flag.Bool("debug", false, "enable debugging")
	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to file")
	flag.Parse()

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	file, err := os.Open("miek.nl.signed")
	defer file.Close()
	if err != nil {
		fmt.Printf("%s\n", err.String())
		return
	}
	p := dns.NewParser(bufio.NewReader(file))
	zone, err = p.Zone()
	if err != nil {
		fmt.Printf("%s\n", err.String())
		return
	}
	s, err := zone.LookupName("miek.nl.", dns.ClassINET, dns.TypeSOA)
	if err != nil {
		fmt.Printf("%s\n", err.String())
		return
	}
	soa = s.RRs[0]

	s1, err := zone.LookupName("miek.nl.", dns.ClassINET, dns.TypeNS)
	if err != nil {
		fmt.Printf("%s\n", err.String())
		return
	}
	ns = s1.RRs
	if len(s1.RRsigs) > 0 {
		nsDNSSEC = ns
		for _, r := range s.RRsigs {
			nsDNSSEC = append(nsDNSSEC, r)
		}
	}

	spam := "Proudly served by Go: http://www.golang.org"
	spamIN = &dns.RR_TXT{Hdr: dns.RR_Header{Name: "miek.nl.", Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: spam}
	spamCH = &dns.RR_TXT{Hdr: dns.RR_Header{Name: "miek.nl.", Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS}, Txt: spam}

	dns.HandleFunc("miek.nl.", handleQuery)
	dns.HandleFunc("bind.", handleQueryCHAOS)
	dns.HandleFunc("server.", handleQueryCHAOS)
	go func() {
		err := dns.ListenAndServe(":8053", "udp", nil)
		if err != nil {

		}
	}()
	go func() {
		err := dns.ListenAndServe(":8053", "tcp", nil)
		if err != nil {

		}
	}()
forever:
	for {
		select {
		case <-signal.Incoming:
			fmt.Printf("Signal received, stopping\n")
			break forever
		}
	}
}
