package main

// Print the version.bind and hostname.bind for each
// address of NAMESERVER
// (c) Miek Gieben - 2011
import (
	"dns"
	"os"
	"fmt"
	"net"
)

func main() {
	r := new(dns.Resolver)
        r.FromFile("/etc/resolv.conf")
	if len(os.Args) != 2 {
		fmt.Printf("%s DOMAIN\n", os.Args[0])
		os.Exit(1)
	}

	m := new(dns.Msg)
	m.Question = make([]dns.Question, 1)
	for _, a := range addresses(r, os.Args[0]) {
		// set the resolver to query the NS directly
		r.Servers = []string{a.String()}
		m.Question[0] = dns.Question{"version.bind.", dns.TypeTXT, dns.ClassCHAOS}
                in, _ := r.Query(m)
		if in != nil && in.Answer != nil {
			fmt.Printf("%v\n", in.Answer[0])
		}
		m.Question[0] = dns.Question{"hostname.bind.", dns.TypeTXT, dns.ClassCHAOS}
                in, _ = r.Query(m)
		if in != nil && in.Answer != nil {
			fmt.Printf("%v\n", in.Answer[0])
		}
	}
}

func addresses(r *dns.Resolver, name string) []net.IP {
	m := new(dns.Msg)
	m.MsgHdr.RecursionDesired = true //only set this bit
	m.Question = make([]dns.Question, 1)
	var ips []net.IP

	m.Question[0] = dns.Question{os.Args[1], dns.TypeA, dns.ClassINET}
        in, err := r.Query(m)
        if in == nil {
                fmt.Printf("Nothing recevied: %s\n", err.String())
                return nil
        }

	if in.Rcode != dns.RcodeSuccess {
		return nil
	}
	// Stuff must be in the answer section
	for _, a := range in.Answer {
		ips = append(ips, a.(*dns.RR_A).A)
	}
	m.Question[0] = dns.Question{os.Args[1], dns.TypeAAAA, dns.ClassINET}
        in, err = r.Query(m)
        if in == nil {
                fmt.Printf("Nothing recevied: %s\n", err.String())
                return nil
        }

	if in.Rcode != dns.RcodeSuccess {
		return nil
	}
	// Stuff must be in the answer section
	for _, a := range in.Answer {
		ips = append(ips, a.(*dns.RR_AAAA).AAAA)
	}
	return ips
}
