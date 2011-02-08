package main

import (
        "fmt"
        "dns"
)

func main() {
	res := new(dns.Resolver)
	res.FromFile("/etc/resolv.conf")

        ch := make(chan *dns.Msg)

	m := new(dns.Msg)
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{"atoom.net", dns.TypeAXFR, dns.ClassINET}

        go res.Axfr(m, ch)
	for x := range ch {
                fmt.Printf("%v\n",x)
        }
}
