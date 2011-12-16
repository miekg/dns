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
	m.SetQuestion(os.Args[1], dns.TypeDNSKEY)

	// Set EDNS0's Do bit
	e := new(dns.RR_OPT)
	e.Hdr.Name = "."
	e.Hdr.Rrtype = dns.TypeOPT
	e.SetUDPSize(2048)
	e.SetDo()
	m.Extra = append(m.Extra, e)

	c := dns.NewClient()
        r, _ := c.Exchange(m, conf.Servers[0] + ":" + conf.Port)
	if r == nil {
		fmt.Printf("*** no answer received for %s\n", os.Args[1])
		os.Exit(1)
	}

	if r.Rcode != dns.RcodeSuccess {
		fmt.Printf(" *** invalid answer name %s after DNSKEY query for %s\n", os.Args[1], os.Args[1])
		os.Exit(1)
	}
	// Stuff must be in the answer section, check len(r.Answer)
	for _, k := range r.Answer {
		// For each key would need to provide a DS records, both sha1 and sha256
                // Maybe print the key flags?
		if key, ok := k.(*dns.RR_DNSKEY); ok {
			key.Hdr.Ttl = 0
                        switch key.Flags {
                        case 256:
                                fmt.Printf("; ZSK\n")
                        case 257:
                                fmt.Printf("; KSK\n")
                        default:
                                fmt.Printf("; %d\n", key.Flags)
                        }

			ds := key.ToDS(dns.SHA1)
			fmt.Printf("%v\n", ds)
			ds = key.ToDS(dns.SHA256)
			fmt.Printf("%v\n", ds)
			ds = key.ToDS(dns.SHA384)
			fmt.Printf("%v\n", ds)
		}
	}
}
