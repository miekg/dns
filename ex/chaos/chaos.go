// Chaos is a small program that prints the version.bind and hostname.bind
// for each address of the nameserver given as argument.
package main

import (
	"fmt"
	"github.com/miekg/dns"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("%s NAMESERVER\n", os.Args[0])
		os.Exit(1)
	}
	conf, _ := dns.ClientConfigFromFile("/etc/resolv.conf")

	m := new(dns.Msg)
	m.Question = make([]dns.Question, 1)
	c := new(dns.Client)

	addr := addresses(conf, c, os.Args[1])
	if len(addr) == 0 {
		fmt.Printf("No address found for %s\n", os.Args[1])
		os.Exit(1)
	}
	for _, a := range addr {
		m.Question[0] = dns.Question{"version.bind.", dns.TypeTXT, dns.ClassCHAOS}
		in, rtt, _ := c.ExchangeRtt(m, a)
		if in != nil && len(in.Answer) > 0 {
			fmt.Printf("(time %.3d µs) %v\n", rtt/1e3, in.Answer[0])
		}
		m.Question[0] = dns.Question{"hostname.bind.", dns.TypeTXT, dns.ClassCHAOS}
		in, rtt, _ = c.ExchangeRtt(m, a)
		if in != nil && len(in.Answer) > 0 {
			fmt.Printf("(time %.3d µs) %v\n", rtt/1e3, in.Answer[0])
		}
	}
}

func qhandler(m, r *dns.Msg, e error, data interface{}) {
	ips := make([]string, 0)
	if r != nil && r.Rcode == dns.RcodeSuccess {
		for _, aa := range r.Answer {
			switch aa.(type) {
			case *dns.RR_A:
				ips = append(ips, aa.(*dns.RR_A).A.String()+":53")
			case *dns.RR_AAAA:
				ips = append(ips, "["+aa.(*dns.RR_AAAA).AAAA.String()+"]:53")
			}
		}
		data.(chan []string) <- ips
		return
	}
	data.(chan []string) <- nil
}

func addresses(conf *dns.ClientConfig, c *dns.Client, name string) []string {
	m4 := new(dns.Msg)
	m4.SetQuestion(dns.Fqdn(os.Args[1]), dns.TypeA)
	m6 := new(dns.Msg)
	m6.SetQuestion(dns.Fqdn(os.Args[1]), dns.TypeAAAA)

	addr := make(chan []string)
	defer close(addr)
	c.Do(m4, conf.Servers[0]+":"+conf.Port, addr, qhandler)
	c.Do(m6, conf.Servers[0]+":"+conf.Port, addr, qhandler)

	var ips []string
	i := 2 // two outstanding queries
forever:
	for {
		select {
		case ip := <-addr:
			ips = append(ips, ip...)
			i--
			if i == 0 {
				break forever
			}
		}
	}
	return ips
}
