package main

import (
	"os"
	"dns"
	"fmt"
	"bufio"
	"os/signal"
)

// A small nameserver implementation.
// Not too fast.

var zone *dns.Zone

func send(w dns.ResponseWriter, m *dns.Msg) {
	buf, _ := m.Pack()
	w.Write(buf)
}

func handleQueryCHAOS(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	qname := req.Question[0].Name
	qtype := req.Question[0].Qtype
	qclass := req.Question[0].Qclass

        println(req.String())

	if qclass != dns.ClassCHAOS {
		m.SetRcode(req, dns.RcodeServerFailure)
		send(w, m)
		return
	}

	if qname == "version.bind." && qtype == dns.TypeTXT {
		m.SetReply(req)
		m.Answer = make([]dns.RR, 1)
		m.Answer[0] = &dns.RR_TXT{Hdr: dns.RR_Header{Name: qname,
			Rrtype: qtype, Class: qclass}, Txt: "NS 0.0.1"}
		send(w, m)
		return
	}
	if qname == "authors.bind." && qtype == dns.TypeTXT {
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
	m := new(dns.Msg)
	qname := req.Question[0].Name
	qtype := req.Question[0].Qtype
	qclass := req.Question[0].Qclass

        println(req.String())

	if qclass != dns.ClassINET {
		m.SetRcode(req, dns.RcodeServerFailure)
		send(w, m)
		return
	}
	m.SetReply(req)

        // Create AUTH section
        m.Ns = make([]dns.RR, 0)
	for i := 0; i < zone.Len(); i++ {
                if zone.At(i).Header().Name == "miek.nl." && zone.At(i).Header().Rrtype == dns.TypeNS {
                        m.Ns = append(m.Ns, zone.At(i))
                }
        }

        // Save the name
        m.Answer = make([]dns.RR, 0)
	for i := 0; i < zone.Len(); i++ {
                if zone.At(i).Header().Name == qname {
                        // Name found
                        if zone.At(i).Header().Rrtype == qtype {
                                // Type also found, exact match
                                m.Answer = append(m.Answer, zone.At(i))
                        }
                }
	}
        // Glue??
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

	dns.HandleFunc("miek.nl.", handleQuery)
	dns.HandleFunc("bind.", handleQueryCHAOS)
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
