package main

import (
        "fmt"
        "dns"
        "flag"
)


func main() {
        var serial *int = flag.Int("serial", 0, "Perform an IXFR with the given serial")
        var onesoa *bool = flag.Bool("1soa", false, "Don't print the last SOA")

        flag.Parse()

	res := new(dns.Resolver)
	res.FromFile("/etc/resolv.conf")

        ch := make(chan dns.RR)

	m := new(dns.Msg)
	m.Question = make([]dns.Question, 1)
        if *serial > 0 {
	        m.Question[0] = dns.Question{"miek.nl.", dns.TypeIXFR, dns.ClassINET}
                soa := new(dns.RR_SOA)
                soa.Hdr = dns.RR_Header{"miek.nl.", dns.TypeSOA, dns.ClassINET, 14400, 0}
                soa.Serial = uint32(*serial)
                m.Ns = make([]dns.RR, 1)
                m.Ns[0] = soa
                go res.Ixfr(m, ch)
        } else {
	        m.Question[0] = dns.Question{"miek.nl.", dns.TypeAXFR, dns.ClassINET}
                go res.Axfr(m, ch)
        }

        soa := false
        for x := range ch {
                if x.Header().Rrtype == dns.TypeSOA {
                        if *onesoa && soa {
                                continue
                        }
                        soa = true
                }
                fmt.Printf("%v\n",x)
        }
}
