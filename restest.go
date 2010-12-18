package main

import (
	"dns"
	"time"
	"fmt"
)

const (
	NLOOP = 5
)

func main() {
	res := new(dns.Resolver)
	ch  := dns.NewQuerier(res)

	// configure the resolver
	res.Servers = []string{"192.168.1.2"}
	res.Timeout = 2
	res.Attempts = 1

	// Setup done, now for some real work
	// Create a new message
	m := new(dns.Msg)
	m.MsgHdr.Recursion_desired = true //only set this bit
	m.Question = make([]dns.Question, 1)

	for i:=0; i< NLOOP; i++ {
		// ask something
		m.Question[0] = dns.Question{"miek.nl", dns.TypeSOA, dns.ClassINET}
		ch <- dns.DnsMsg{m, nil}

		// wait for an reply
		in := <-ch
		fmt.Printf("%v\n", in.Dns)

		m.Question[0] = dns.Question{"a.miek.nl", dns.TypeTXT, dns.ClassINET}
		ch <- dns.DnsMsg{m, nil}
		in = <-ch
		fmt.Printf("%v\n", in.Dns)

		m.Question[0] = dns.Question{"miek.nl", dns.TypeTXT, dns.ClassINET}
		ch <- dns.DnsMsg{m, nil}
		in = <-ch
		fmt.Printf("%v\n", in.Dns)
	}
	ch <- dns.DnsMsg{nil, nil}

	time.Sleep(2.0e9) // wait for Go routine to do something
}
