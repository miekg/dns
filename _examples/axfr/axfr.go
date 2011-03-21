package main

import (
        "fmt"
        "dns"
        "flag"
)


func main() {
        var serial *int = flag.Int("serial", 0, "Perform an IXFR with the given serial")
        var nameserver *string = flag.String("ns", "127.0.0.1", "Query this nameserver")
        flag.Parse()
        zone := flag.Arg(flag.NArg()-1)

	res := new(dns.Resolver)
	res.FromFile("/etc/resolv.conf")
        res.Servers[0] = *nameserver

        c := make(chan dns.Xfr)
	m := new(dns.Msg)
	m.Question = make([]dns.Question, 1)

        if *serial > 0 {
	        m.Question[0] = dns.Question{zone, dns.TypeIXFR, dns.ClassINET}
                soa := new(dns.RR_SOA)
                soa.Hdr = dns.RR_Header{zone, dns.TypeSOA, dns.ClassINET, 14400, 0}
                soa.Serial = uint32(*serial)
                m.Ns = make([]dns.RR, 1)
                m.Ns[0] = soa
        } else {
	        m.Question[0] = dns.Question{zone, dns.TypeAXFR, dns.ClassINET}
        }
        go res.Xfr(m, nil, c)
        for x := range c {
                fmt.Printf("%v %v\n",x.Add, x.RR)
        }
}
