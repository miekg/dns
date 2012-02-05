package main

import (
	"dns"
	"flag"
	"fmt"
)

func main() {
	var serial *int = flag.Int("serial", 0, "Perform an IXFR with the given serial")
	var nameserver *string = flag.String("ns", "127.0.0.1:53", "Query this nameserver")
	//	var secret *string = flag.String("secret", "", "Use this secret for TSIG")
	flag.Parse()
	zone := flag.Arg(flag.NArg() - 1)

	client := dns.NewClient()
	client.Net = "tcp"
	m := new(dns.Msg)
	if *serial > 0 {
		m.SetIxfr(zone, uint32(*serial))
	} else {
		m.SetAxfr(zone)
	}
	if err := client.XfrReceive(m, *nameserver); err == nil {
		for r := range client.ReplyChan {
			if r.Error != nil {
				if r.Error == dns.ErrXfrLast {
					fmt.Printf("%v\n", r.Reply)
				}
				break
			}
			fmt.Printf("%v\n", r.Reply)
		}
	} else {
		fmt.Printf("Error %v\n", err)
	}
}
