package main

import (
	"dns"
	"time"
	"fmt"
)

const (
	NLOOP = 5
)

func identity(msg []byte) []byte {
	return msg
}

func byteflip(msg []byte) []byte {
	msg[len(msg) - 1] = 0
	msg[2] = 0		// See what happens
	return msg
}

func bitflip(msg []byte) []byte {
	return msg
}

func main() {
	res := new(dns.Resolver)
	ch  := dns.NewQuerier(res)

	// configure the resolver
	res.Servers = []string{"192.168.1.2"}
	res.Timeout = 2
	res.Attempts = 1
	res.Mangle = byteflip

	// Setup done, now for some real work
	// Create a new message
	m := new(dns.Msg)
	m.MsgHdr.Recursion_desired = true //only set this bit
	m.Question = make([]dns.Question, 1)

		// ask something
		m.Question[0] = dns.Question{"miek.nl", dns.TypeSOA, dns.ClassINET}
		ch <- dns.DnsMsg{m, nil}

		// wait for an reply
		in := <-ch
		fmt.Printf("%v\n", in.Dns)

	ch <- dns.DnsMsg{nil, nil}

	time.Sleep(1.0e9) // wait for Go routine to do something
}
