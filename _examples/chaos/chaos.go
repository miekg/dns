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
	if len(os.Args) != 2 {
		fmt.Printf("%s NAMESERVER\n", os.Args[0])
		os.Exit(1)
	}
	conf, _ := dns.ClientConfigFromFile("/etc/resolv.conf")

	m := new(dns.Msg)
	m.Question = make([]dns.Question, 1)
        c := dns.NewClient()

        // Todo: in parallel
        addr := addresses(conf, c, os.Args[0])
        if len(addr) == 0 {
                fmt.Printf("No address found for %s\n", os.Args[1])
                os.Exit(1)
        }
	for _, a := range addr {
		m.Question[0] = dns.Question{"version.bind.", dns.TypeTXT, dns.ClassCHAOS}
		in := c.Exchange(m, a)
		if in != nil && in.Answer != nil {
			fmt.Printf("%v\n", in.Answer[0])
		}
		m.Question[0] = dns.Question{"hostname.bind.", dns.TypeTXT, dns.ClassCHAOS}
		in = c.Exchange(m, a)
		if in != nil && in.Answer != nil {
			fmt.Printf("%v\n", in.Answer[0])
		}
	}
}

func addresses(conf *dns.ClientConfig, c *dns.Client, name string) []string {
	m := new(dns.Msg)
        m.SetQuestion(os.Args[1], dns.TypeA)     // Allocates space
	var ips []string

	r := c.Exchange(m, conf.Servers[0])
	if r == nil {
		fmt.Printf("Nothing recevied for %s\n", name)
		return nil
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil
	}
	for _, a := range r.Answer {
		ips = append(ips, a.(*dns.RR_A).A.String()+":53")
	}

        m.SetQuestion(os.Args[1], dns.TypeAAAA)
	r = c.Exchange(m, conf.Servers[0])
	if r == nil {
		fmt.Printf("Nothing recevied for %s\n", name)
		return ips
	}
	if r.Rcode != dns.RcodeSuccess {
		return ips
	}
	for _, a := range r.Answer {
		ips = append(ips, "["+a.(*dns.RR_AAAA).AAAA.String()+"]:53")
	}

	return ips
}
