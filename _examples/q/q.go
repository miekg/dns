package main

import (
	"net"
	"dns"
	"dns/resolver"
	"os"
	"flag"
	"fmt"
)

var Usage = func() {
	fmt.Fprintf(os.Stderr, "Usage: %s [@server] [qtype] [qclass] [name ...]\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	var dnssec *bool = flag.Bool("dnssec", false, "Set the DO (DNSSEC OK) bit and set the bufsize to 4096")
	nameserver := "127.0.0.1"       // Default nameserver
	qtype := uint16(dns.TypeA)      // Default qtype
	qclass := uint16(dns.ClassINET) // Default qclass
	var qname []string

	flag.Parse()

	if *dnssec {
		/* */
	}
FLAGS:
	for i := 0; i < flag.NArg(); i++ {
		// If it starts with @ it is a nameserver
		if flag.Arg(i)[0] == '@' {
			nameserver = flag.Arg(i)
			continue FLAGS
		}
		// If it looks like a class, it is a class
		for k, v := range dns.Class_str {
			if v == flag.Arg(i) {
				qclass = k
				continue FLAGS
			}
		}
		// And if it looks like type, it is a type
		for k, v := range dns.Rr_str {
			if v == flag.Arg(i) {
				qtype = k
				continue FLAGS
			}
		}
		// Anything else is a qname
		qname = append(qname, flag.Arg(i))
	}
	r := new(resolver.Resolver)
        r.Timeout = 2
        r.Attempts = 1

	qr := resolver.NewQuerier(r)
	// @server may be a name, resolv that 
	var err os.Error
	_, addr, err := net.LookupHost(nameserver)
        if err == nil {
                r.Servers = addr
        } else {
                r.Servers = []string{nameserver}
        }

	m := new(dns.Msg)
	m.Question = make([]dns.Question, 1)
	for _, v := range qname {
		m.Question[0] = dns.Question{v, qtype, qclass}
		qr <- resolver.DnsMsg{m, nil}
		in := <-qr
		if in.Dns != nil {
			fmt.Printf("%v\n", in.Dns)
		}
	}
	qr <- resolver.DnsMsg{nil, nil}
	<-qr
}
