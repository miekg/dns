package main

import (
	"dns"
	"flag"
	"fmt"
	"strings"
	"time"
)

func main() {
	serial := flag.Int("serial", 0, "Perform an IXFR with the given serial")
	nameserver := flag.String("ns", "127.0.0.1:53", "Query this nameserver")
	tsig := flag.String("tsig", "", "request tsig with key: name:key (only hmac-md5)")
	flag.Parse()
	zone := flag.Arg(flag.NArg() - 1)

	client := new(dns.Client)
	client.Net = "tcp"
	m := new(dns.Msg)
	if *serial > 0 {
		m.SetIxfr(zone, uint32(*serial))
	} else {
		m.SetAxfr(zone)
	}
	if *tsig != "" {
		a := strings.SplitN(*tsig, ":", 2)
		name, secret := a[0], a[1]
		client.TsigSecret = map[string]string{name: secret}
		m.SetTsig(name, dns.HmacMD5, 300, time.Now().Unix())
	}

	if t, e := client.XfrReceive(m, *nameserver); e == nil {
		for r := range t {
			if r.Error == nil {
				fmt.Printf("%v\n", r.Reply)
			}
		}
	} else {
		fmt.Printf("Error %v\n", e)
	}
}
