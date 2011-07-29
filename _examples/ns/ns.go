package main

import (
	"os"
	"dns"
	"fmt"
	"bufio"
        "strings"
	"os/signal"
)

// A small nameserver implementation, not too fast.
var (
	zone   *dns.Zone
	ns     []dns.RR
	soa    dns.RR
	spamIN dns.RR
	spamCH dns.RR
)

func send(w dns.ResponseWriter, m *dns.Msg) {
	buf, _ := m.Pack()
	w.Write(buf)
}

func handleQueryCHAOS(w dns.ResponseWriter, req *dns.Msg) {
	println(req.String())
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
	println(req.String())
	m := new(dns.Msg)
	qname := req.Question[0].Name
	qtype := req.Question[0].Qtype
	qclass := req.Question[0].Qclass
	m.Extra = make([]dns.RR, 1)
	m.Extra[0] = spamIN

	if qclass != dns.ClassINET {
		m.SetRcode(req, dns.RcodeServerFailure)
		send(w, m)
		return
	}
	m.SetReply(req)

	m.Ns = ns

	names := false
	cname := 0
	m.Answer = make([]dns.RR, 0)
again:
	for i := 0; i < zone.Len(); i++ {
		if zone.At(i).Header().Name == qname {
			names = true
			// Name found
			if zone.At(i).Header().Rrtype == qtype {
				// Exact match
				m.Answer = append(m.Answer, zone.At(i))
			}
			if zone.At(i).Header().Rrtype == dns.TypeCNAME {
				// Cname match
				m.Answer = append(m.Answer, zone.At(i))
				qname = zone.At(i).(*dns.RR_CNAME).Cname
				cname++
				if cname > 7 {
					break
				}
				goto again
			}
		}
	}
	if len(m.Answer) == 0 {
		m.Ns = m.Ns[:1]
		m.Ns[0] = soa
		if !names {
			// NXDOMAIN
			m.MsgHdr.Rcode = dns.RcodeNameError
		}
	}
	// Glue?? TODO
	send(w, m)
}

func main() {
	file, err := os.Open("miek.nl.signed")
	defer file.Close()
	if err != nil {
		return
	}
	p := dns.NewParser(bufio.NewReader(file))
	zone, err = p.Zone()
	if err != nil {

	}

	ns = make([]dns.RR, 0)
	for i := 0; i < zone.Len(); i++ {
		if zone.At(i).Header().Name == "miek.nl." && zone.At(i).Header().Rrtype == dns.TypeSOA {
			soa = zone.At(i)
		}
		if zone.At(i).Header().Name == "miek.nl." && zone.At(i).Header().Rrtype == dns.TypeNS {
			ns = append(ns, zone.At(i))
		}
	}
	s := "Proudly served with Go: http://www.golang.org"
	spamIN = &dns.RR_TXT{Hdr: dns.RR_Header{Name: "miek.nl.", Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: s}
	spamCH = &dns.RR_TXT{Hdr: dns.RR_Header{Name: "miek.nl.", Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS}, Txt: s}

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
