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

	client := dns.NewClient()
	client.Net = "tcp"
	m := new(dns.Msg)
	m.MsgHdr.Id = dns.Id()
	if *serial > 0 {
		m.SetIxfr(zone, uint32(*serial))
	} else {
		m.SetAxfr(zone)
	}
	if *tsig != "" {
		a := strings.SplitN(*tsig, ":", 2)
		name, secret := a[0], a[1]
		client.TsigSecret = map[string]string{name: secret}
		m.SetTsig(name, dns.HmacMD5, 300, m.MsgHdr.Id, time.Now().Unix())
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
