package main

// Simple prog that "validates" a reply from a
// server, but DOES NOT check the chain of trust!

// lutser is Dutch for prutser and looser combined
// so zlutser does that with zones

import (
	"net"
	"dns"
	"dns/resolver"
	"os"
	"flag"
	"fmt"
	"strings"
)

func main() {
	var tcp *bool = flag.Bool("tcp", true, "TCP mode")
	var port *string = flag.String("port", "53", "Set the query port")
	var zone *string = flag.String("zone", "", "Zone to ask the DNSKEYs for")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -z zone [@server] [qtype] [name ...]\n", os.Args[0])
		// extend this a little
		flag.PrintDefaults()
	}

	nameserver := "@127.0.0.1"      // Default nameserver
	qtype := uint16(dns.TypeA)      // Default qtype
	var qname []string

	flag.Parse()

	if *zone == "" {
		fmt.Fprintf(os.Stderr, "%s: -zone is mandatory\n", os.Args[0])
		os.Exit(1)
	}

FLAGS:
	for i := 0; i < flag.NArg(); i++ {
		// If it starts with @ it is a nameserver
		if flag.Arg(i)[0] == '@' {
			nameserver = flag.Arg(i)
			continue FLAGS
		}
		// If it looks like type, it is a type
		for k, v := range dns.Rr_str {
			if v == strings.ToUpper(flag.Arg(i)) {
				qtype = k
				continue FLAGS
			}
		}
		// Anything else is a qname
		qname = append(qname, flag.Arg(i))
	}
	r := new(resolver.Resolver)
	r.Timeout = 2
	r.Port = *port
	r.Tcp = *tcp
	r.Attempts = 1

	qr := r.NewQuerier()
	// @server may be a name, resolv that 
	var err os.Error
	nameserver = string([]byte(nameserver)[1:]) // chop off @
	_, addr, err := net.LookupHost(nameserver)
	if err == nil {
		r.Servers = addr
	} else {
		r.Servers = []string{nameserver}
	}

	m := new(dns.Msg)
//	m.MsgHdr.Authoritative = *aa
//	m.MsgHdr.AuthenticatedData = *ad
	m.MsgHdr.CheckingDisabled = true
	m.MsgHdr.RecursionDesired = true
	m.Question = make([]dns.Question, 1)
	// set the do bit
	opt := new(dns.RR_OPT)
	opt.Hdr = dns.RR_Header{Name: "", Rrtype: dns.TypeOPT}
	opt.Version(0, true)
	opt.DoBit(true, true)
	opt.UDPSize(4096, true)
	m.Extra = make([]dns.RR, 1)
	m.Extra[0] = opt

	for _, v := range qname {
		// Ask the Keys
		m.Question[0] = dns.Question{*zone, dns.TypeDNSKEY, dns.ClassINET}
		qr <- resolver.DnsMsg{m, nil}
		in := <-qr
		if in.Dns != nil {
			fmt.Printf("%v\n", in.Dns)
		}

		m.Question[0] = dns.Question{v, qtype, dns.ClassINET}
		qr <- resolver.DnsMsg{m, nil}
		in = <-qr
		if in.Dns != nil {
			fmt.Printf("%v\n", in.Dns)
		}

		// Ask the question
		// Get the sig(s)

		// Use the key(s)

		// Validate

	}
	qr <- resolver.DnsMsg{nil, nil}
	<-qr
}
