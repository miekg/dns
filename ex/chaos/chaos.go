// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Chaos is a small program that prints the version.bind and hostname.bind
// for each address of the nameserver given as argument.
package main

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
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

func do(t chan *dns.Msg, c *dns.Client, m *dns.Msg, addr string) {
	go func() {
		r, _, err := c.Exchange(m, addr)
		if err != nil {
			//print error stuff
			t <- nil
		}
		t <- r
	}()
}

func addresses(conf *dns.ClientConfig, c *dns.Client, name string) (ips []string) {
	m4 := new(dns.Msg)
	m4.SetQuestion(dns.Fqdn(os.Args[1]), dns.TypeA)
	m6 := new(dns.Msg)
	m6.SetQuestion(dns.Fqdn(os.Args[1]), dns.TypeAAAA)
	t := make(chan *dns.Msg)
	defer close(t)
	do(t, c, m4, net.JoinHostPort(conf.Servers[0], conf.Port))
	do(t, c, m6, net.JoinHostPort(conf.Servers[0], conf.Port))

	i := 2 // two outstanding queries
forever:
	for {
		select {
		case d := <-t:
			i--
			if d == nil {
				continue
			}
			if i == 0 {
				break forever
			}
			if d.Rcode == dns.RcodeSuccess {
				for _, a := range d.Answer {
					switch a.(type) {
					case *dns.A:
						ips = append(ips,
							net.JoinHostPort(a.(*dns.A).A.String(), "53"))
					case *dns.AAAA:
						ips = append(ips,
							net.JoinHostPort(a.(*dns.AAAA).AAAA.String(), "53"))

					}
				}
			}
		}
	}
	return ips
}
