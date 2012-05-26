package main

// Print the DNSKEY records of a domain as DS records
// Twist with all the other tools that can do this. Do
// this directly from the internet.
// (c) Miek Gieben - 2011
import (
	"dns"
	"fmt"
	"os"
)

func main() {
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if len(os.Args) != 2 || err != nil {
		fmt.Printf("%s DOMAIN\n", os.Args[0])
		os.Exit(1)
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(os.Args[1]), dns.TypeDNSKEY)
	m.SetEdns0(2048, true)

	c := dns.NewClient()
	r, _ := c.Exchange(m, conf.Servers[0]+":"+conf.Port)
	if r == nil {
		fmt.Printf("*** no answer received for %s\n", os.Args[1])
		os.Exit(1)
	}

	if r.Rcode != dns.RcodeSuccess {
		fmt.Printf(" *** invalid answer name %s after DNSKEY query for %s\n", os.Args[1], os.Args[1])
		os.Exit(1)
	}
	for _, k := range r.Answer {
		if key, ok := k.(*dns.RR_DNSKEY); ok {
			key.Hdr.Ttl = 0
			for _, alg := range []int{dns.SHA1, dns.SHA256, dns.SHA384} {
				ds := key.ToDS(alg)
				fmt.Printf("%v; %d\n", ds, key.Flags)
			}
		}
	}
}
