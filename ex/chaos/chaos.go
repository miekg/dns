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
		in, rtt, _ := c.Exchange(m, a)
		if in != nil && len(in.Answer) > 0 {
			fmt.Printf("(time %.3d µs) %v\n", rtt/1e3, in.Answer[0])
		}
		m.Question[0] = dns.Question{"hostname.bind.", dns.TypeTXT, dns.ClassCHAOS}
		in, rtt, _ = c.Exchange(m, a)
		if in != nil && len(in.Answer) > 0 {
			fmt.Printf("(time %.3d µs) %v\n", rtt/1e3, in.Answer[0])
		}
	}
}

func addresses(conf *dns.ClientConfig, c *dns.Client, name string) (ips []string) {
	m4 := new(dns.Msg)
	m4.SetQuestion(dns.Fqdn(os.Args[1]), dns.TypeA)
	m6 := new(dns.Msg)
	m6.SetQuestion(dns.Fqdn(os.Args[1]), dns.TypeAAAA)
	c4 := c.Do(m4, conf.Servers[0]+":"+conf.Port)
	c6 := c.Do(m6, conf.Servers[0]+":"+conf.Port)

	i := 2 // two outstanding queries
forever:
	for {
		select {
		case ip4 := <-c4:
			if ip4.Reply != nil && ip4.Reply.Rcode == dns.RcodeSuccess {
				for _, a := range ip4.Reply.Answer {
					switch a.(type) {
					case *dns.RR_A:
						ips = append(ips, a.(*dns.RR_A).A.String()+":53")

					}
				}
			}
			i--
			if i == 0 {
				break forever
			}
		case ip6 := <-c6:
			if ip6.Reply != nil && ip6.Reply.Rcode == dns.RcodeSuccess {
				for _, a := range ip6.Reply.Answer {
					switch a.(type) {
					case *dns.RR_AAAA:
						ips = append(ips, a.(*dns.RR_AAAA).AAAA.String()+":53")

					}
				}
			}
			i--
			if i == 0 {
				break forever
			}

		}
	}
	return ips
}
