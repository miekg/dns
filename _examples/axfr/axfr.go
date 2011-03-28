package main

import (
	"fmt"
	"dns"
	"flag"
)

func main() {
	var serial *int = flag.Int("serial", 0, "Perform an IXFR with the given serial")
	var nameserver *string = flag.String("ns", "127.0.0.1:53", "Query this nameserver")
	flag.Parse()
	zone := flag.Arg(flag.NArg() - 1)

	c := make(chan dns.Xfr)
	d := new(dns.Conn)
	m := new(dns.Msg)

	d.RemoteAddr = *nameserver
	if *serial > 0 {
		m.SetIxfr(zone, uint32(*serial))
	} else {
		m.SetAxfr(zone)
	}
	go d.XfrRead(m, c)
	for x := range c {
		fmt.Printf("%v %v %v\n", x.Add, x.RR, x.Err)
	}
}
