package main

import (
        "fmt"
        "dns"
        "dns/resolver"
)

func main() {
	res := new(resolver.Resolver)
	ch := res.NewXfer()

	res.Servers = []string{"127.0.0.1"}
	m := new(dns.Msg)
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{"atoom.net", dns.TypeAXFR, dns.ClassINET}

        ch <- resolver.DnsMsg{m, nil}
	for dm := range ch {
                fmt.Printf("%v\n",dm.Dns)
        }
}
