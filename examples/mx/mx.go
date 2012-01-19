package main
// Print the MX records of a domain
// (c) Miek Gieben - 2011
import (
	"dns"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("%s DOMAIN\n", os.Args[0])
		os.Exit(1)
	}

	// Error checking
	config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	c := dns.NewClient()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(os.Args[1]), dns.TypeMX)
	m.MsgHdr.RecursionDesired = true

	// Simple sync query, nothing fancy
        r, err := c.Exchange(m, config.Servers[0] + ":" + config.Port)
	if err != nil {
		fmt.Printf("%s\n", err.Error())
		os.Exit(1)
	}
	if r.Rcode != dns.RcodeSuccess {
		fmt.Printf(" *** invalid answer name %s after MX query for %s\n", os.Args[1], os.Args[1])
		os.Exit(1)
	}
	// Stuff must be in the answer section
	for _, a := range r.Answer {
		fmt.Printf("%v\n", a)
	}
}
