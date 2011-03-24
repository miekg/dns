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

        if *serial > 0 {
                m.SetIxfr(zone, uint32(*serial))
        } else {
                m.SetAxfr(zone)
        }
        go res.Xfr(m, c)
        for x := range c {
                if x.Err != nil {
                        fmt.Printf("%v\n",x.Err)
                } else {
                        fmt.Printf("%v %v\n",x.Add, x.RR)
                }
        }
}
