package main

// TODO
// error handling and dns errors should be displayed

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
	var dnssec *bool = flag.Bool("dnssec", false, "Set the DO (DNSSEC OK) bit and set the bufsize to 4096")
        var port   *string = flag.String("port", "53", "Set the query port")
        flag.Usage = func() {
                fmt.Fprintf(os.Stderr, "Usage: %s [@server] [qtype] [qclass] [name ...]\n", os.Args[0])
                flag.PrintDefaults()
        }

	nameserver := "@127.0.0.1"       // Default nameserver
	qtype := uint16(dns.TypeA)      // Default qtype
	qclass := uint16(dns.ClassINET) // Default qclass
	var qname []string

	flag.Parse()

FLAGS:
	for i := 0; i < flag.NArg(); i++ {
		// If it starts with @ it is a nameserver
		if flag.Arg(i)[0] == '@' {
			nameserver = flag.Arg(i)
			continue FLAGS
		}
		// If it looks like a class, it is a class
		for k, v := range dns.Class_str {
			if v == strings.ToUpper(flag.Arg(i)) {
				qclass = k
				continue FLAGS
			}
		}
		// And if it looks like type, it is a type
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
        r.Attempts = 1

	qr := resolver.NewQuerier(r)
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
	m.Question = make([]dns.Question, 1)
	if *dnssec {
                opt := new(dns.RR_OPT)
                opt.Hdr = dns.RR_Header{Name: "", Rrtype: dns.TypeOPT}
                opt.Version(0, true)
                opt.DoBit(true, true)
                opt.UDPSize(4096, true)
		m.Extra = make([]dns.RR, 1)
                m.Extra[0] = opt
	}
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
