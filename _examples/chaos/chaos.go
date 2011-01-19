package main

// Print the version.bind and hostname.bind for each
// address of NAMESERVER
// (c) Miek Gieben - 2011
import (
	"dns"
        "dns/resolver"
	"os"
	"fmt"
	"net"
)

func main() {
	r := new(resolver.Resolver)
	qr := r.NewQuerier()
        r.FromFile("/etc/resolv.conf")
	var in resolver.Msg

	if len(os.Args) != 2 {
		fmt.Printf("%s DOMAIN\n", os.Args[0])
		os.Exit(1)
	}

	m := new(dns.Msg)
	m.Question = make([]dns.Question, 1)
	for _, a := range addresses(qr, os.Args[0]) {
		// set the resolver to query the NS directly
		r.Servers = []string{a.String()}
		m.Question[0] = dns.Question{"version.bind.", dns.TypeTXT, dns.ClassCHAOS}
		qr <- resolver.Msg{m, nil, nil}
		in = <-qr
		if in.Dns != nil && in.Dns.Answer != nil {
			fmt.Printf("%v\n", in.Dns.Answer[0])
		}
		m.Question[0] = dns.Question{"hostname.bind.", dns.TypeTXT, dns.ClassCHAOS}
		qr <- resolver.Msg{m, nil, nil}
		in = <-qr
		if in.Dns != nil && in.Dns.Answer != nil {
			fmt.Printf("%v\n", in.Dns.Answer[0])
		}
	}

	// Stop the resolver, send it a null mesg
	qr <- resolver.Msg{}
	<-qr
}

func addresses(qr chan resolver.Msg, name string) []net.IP {
	m := new(dns.Msg)
	m.MsgHdr.RecursionDesired = true //only set this bit
	m.Question = make([]dns.Question, 1)
	var ips []net.IP

	m.Question[0] = dns.Question{os.Args[1], dns.TypeA, dns.ClassINET}
	qr <- resolver.Msg{m, nil, nil}
	in := <-qr

        if in.Dns == nil {
                fmt.Printf("Nothing recevied: %s\n", in.Error.String())
                return nil
        }

	if in.Dns.Rcode != dns.RcodeSuccess {
		return nil
	}
	// Stuff must be in the answer section
	for _, a := range in.Dns.Answer {
		ips = append(ips, a.(*dns.RR_A).A)
	}
	m.Question[0] = dns.Question{os.Args[1], dns.TypeAAAA, dns.ClassINET}
	qr <- resolver.Msg{m, nil, nil}
	in = <-qr

        if in.Dns == nil {
                fmt.Printf("Nothing recevied: %s\n", in.Error.String())
                return nil
        }

	if in.Dns.Rcode != dns.RcodeSuccess {
		return nil
	}
	// Stuff must be in the answer section
	for _, a := range in.Dns.Answer {
		ips = append(ips, a.(*dns.RR_AAAA).AAAA)
	}
	return ips
}
