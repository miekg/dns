package main

import (
        "fmt"
        "dns"
        "flag"
)


func main() {
        var serial *int = flag.Int("serial", 0, "Perform an IXFR with the given serial")
        zone := "tjeb.nl."

        flag.Parse()

	res := new(dns.Resolver)
	res.FromFile("/etc/resolv.conf")
        res.Servers[0] = "open.nlnetlabs.nl"

        a := make(chan dns.RR)
        d := make(chan dns.RR)

	m := new(dns.Msg)
	m.Question = make([]dns.Question, 1)
        if *serial > 0 {
	        m.Question[0] = dns.Question{zone, dns.TypeIXFR, dns.ClassINET}
                soa := new(dns.RR_SOA)
                soa.Hdr = dns.RR_Header{zone, dns.TypeSOA, dns.ClassINET, 14400, 0}
                soa.Serial = uint32(*serial)
                m.Ns = make([]dns.RR, 1)
                m.Ns[0] = soa
                go res.Ixfr(m, a, d)
Loop:
                for {
                select {
                case x := <-a:
                        fmt.Printf("ADD: %v\n",x)
                case x := <-d:
                        fmt.Printf("REM: %v\n",x)
                }
                }
//                if !closed(a) && !closed(d) {
 //                       goto Loop
  //              }
        } else {
	        m.Question[0] = dns.Question{zone, dns.TypeAXFR, dns.ClassINET}
                go res.Axfr(m, a)
                for x := range a {
                        fmt.Printf("%v\n",x)
                }
        }
}
