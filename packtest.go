package main

import (
	"dns"
	"fmt"
	"net"
)

func main() {
	out := new(dns.Msg)

	r := new(dns.RR_AAAA)
	r.AAAA = net.ParseIP("2001:7b8:206:1:200:39ff:fe59:b187").To16()
//	r.AAAA = net.ParseIP("2003::53").To16()
	r.Hdr.Name = "a.miek.nl"
	r.Hdr.Rrtype = dns.TypeAAAA
	r.Hdr.Class = dns.ClassINET
	r.Hdr.Ttl = 3600
	out.Answer = make([]dns.RR, 1)
	out.Answer[0] = r

	msg, _ := out.Pack()

	in := new(dns.Msg)
	in.Unpack(msg)
	fmt.Printf("%v\n", in)
}
