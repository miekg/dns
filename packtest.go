package main

import (
	"dns"
	"fmt"
	"net"
)

func main() {
	res := new(dns.Resolver)
	res.Servers = []string{"192.168.1.2"}
	res.Timeout = 2
	res.Attempts = 1

	a := new(dns.RR_A)
	a.A = net.ParseIP("192.168.1.2").To4()

	aaaa := new(dns.RR_AAAA)
	aaaa.AAAA = net.ParseIP("2003::53").To16()

	fmt.Printf("%v\n", a)
	fmt.Printf("%v\n", aaaa)

//	msg, _ := res.Query("miek.nl.", dns.TypeTXT, dns.ClassINET)
//	fmt.Printf("%v\n", msg)
//
//	msg, _ = res.Query("www.nlnetlabs.nl", dns.TypeAAAA, dns.ClassINET)
//	fmt.Printf("%v\n", msg)
//
	msg, _ := res.Query("nlnetlabs.nl", dns.TypeDNSKEY, dns.ClassINET)
	fmt.Printf("%v\n", msg)

	msg, _ = res.Query("jelte.nlnetlabs.nl", dns.TypeDS, dns.ClassINET)
	fmt.Printf("%v\n", msg)
}
