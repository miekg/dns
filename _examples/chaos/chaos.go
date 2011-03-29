package main

// Print the version.bind and hostname.bind for each
// address of NAMESERVER
// (c) Miek Gieben - 2011
import (
	"dns"
	"os"
	"fmt"
)

func main() {
	c, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	if len(os.Args) != 2 {
		fmt.Printf("%s DOMAIN\n", os.Args[0])
		os.Exit(1)
	}

	m := new(dns.Msg)
	m.Question = make([]dns.Question, 1)
	d := new(dns.Conn)
	d.RemoteAddr = c.Servers[0]
	d.Dial("udp")
	for _, a := range addresses(d, os.Args[0]) {
//                d.Close()     -- interesting
		d.RemoteAddr = a
		d.Dial("udp") // Redial TODO(mg)
		m.Question[0] = dns.Question{"version.bind.", dns.TypeTXT, dns.ClassCHAOS}
		in, _ := dns.QuerySimple(d, m)
		if in != nil && in.Answer != nil {
			fmt.Printf("%v\n", in.Answer[0])
		}
		m.Question[0] = dns.Question{"hostname.bind.", dns.TypeTXT, dns.ClassCHAOS}
		in, _ = dns.QuerySimple(d, m)
		if in != nil && in.Answer != nil {
			fmt.Printf("%v\n", in.Answer[0])
		}
	}
}

func addresses(d *dns.Conn, name string) []string {
	m := new(dns.Msg)
	m.MsgHdr.RecursionDesired = true //only set this bit
	m.Question = make([]dns.Question, 1)
	var ips []string

	m.Question[0] = dns.Question{os.Args[1], dns.TypeA, dns.ClassINET}
	in, err := dns.QuerySimple(d, m)
	if in == nil {
		fmt.Printf("Nothing recevied: %s\n", err.String())
		return nil
	}

	if in.Rcode != dns.RcodeSuccess {
		return nil
	}
	// Stuff must be in the answer section
	for _, a := range in.Answer {
		ips = append(ips, a.(*dns.RR_A).A.String()+":53")
	}
	m.Question[0] = dns.Question{os.Args[1], dns.TypeAAAA, dns.ClassINET}
	in, err = dns.QuerySimple(d, m)
	if in == nil {
		fmt.Printf("Nothing recevied: %s\n", err.String())
		return ips
	}

	if in.Rcode != dns.RcodeSuccess {
		return ips
	}
	// Stuff must be in the answer section
	for _, a := range in.Answer {
		ips = append(ips, a.(*dns.RR_AAAA).AAAA.String()+":53")
	}
	return ips
}
