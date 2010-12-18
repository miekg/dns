package main

import (
	"dns"
	"fmt"
	"time"
)

func main() {
	res := new(dns.Resolver) // create a new resolver

	// Create a new message
	m := new(dns.Msg)
	m.MsgHdr.Recursion_desired = true //only set this bit
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{"miek.nl", dns.TypeSOA, dns.ClassINET}

	// send config (or res with Query)

	msgch := make(chan dns.MsgErr)
	qch := make(chan bool)

	// start the resolver
	go dns.Query(res, msgch, qch)

	// configure the resolver
	res.Servers = []string{"192.168.1.2"}
	res.Timeout = 2
	res.Attempts = 1

	// Setup done, now for some real work

	// ask something
	msgch <- dns.MsgErr{m, nil}

	// wait for an reply
	in := <-msgch
	fmt.Printf("%v\n", in.M)
	// kill resolver
	// qch <- true does not work yet

	m.Question[0] = dns.Question{"a.miek.nl", dns.TypeTXT, dns.ClassINET}
	msgch <- dns.MsgErr{m, nil}
	// wait for an reply
	in = <-msgch
	fmt.Printf("%v\n", in.M)

	m.Question[0] = dns.Question{"miek.nl", dns.TypeTXT, dns.ClassINET}
	// ask something
	msgch <- dns.MsgErr{m, nil}
	// wait for an reply
	in = <-msgch
	fmt.Printf("%v\n", in.M)

	time.Sleep(2.0e9) // wait for Go routine to do something
}
