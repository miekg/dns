package main

import (
	"dns"
	"fmt"
	"time"
)

func main() {
	res := new(dns.Resolver) // create a new resolver
	res.Servers = []string{"192.168.1.2"}
	res.Timeout = 2
	res.Attempts = 1

	// Create a new message
	m := new(dns.Msg)
	m.MsgHdr.Recursion_desired = true //only set this bit
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{"miek.nl", dns.TypeSOA, dns.ClassINET}

	msgch := make(chan dns.MsgErr)
	qch := make(chan bool)

	// start the resolver
	go res.Query(msgch, qch)

	// ask something
	msgch <- dns.MsgErr{m, nil}

	// wait for an reply
	in := <-msgch
	fmt.Printf("%v\n", in.M)
	// kill resolver
	// qch <- true does not work yet
	time.Sleep(2.0e9)

	/*
		a := new(dns.RR_A)
		a.A = net.ParseIP("192.168.1.2").To4()

		aaaa := new(dns.RR_AAAA)
		aaaa.AAAA = net.ParseIP("2003::53").To16()

		fmt.Printf("%v\n", a)
		fmt.Printf("%v\n", aaaa)

	//	msg, _ := res.Query("miek.nl.", dns.TypeTXT, dns.ClassINET)
	//
	//	msg, _ = res.Query("www.nlnetlabs.nl", dns.TypeAAAA, dns.ClassINET)
	//	fmt.Printf("%v\n", msg)
	//
		msg, _ := res.Query("nlnetlabs.nl", dns.TypeDNSKEY, dns.ClassINET)
		fmt.Printf("%v\n", msg)

		msg, _ = res.Query("jelte.nlnetlabs.nl", dns.TypeDS, dns.ClassINET)
		fmt.Printf("%v\n", msg)
	*/
}
