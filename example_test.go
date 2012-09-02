package dns

import (
	"fmt"
)

// Retrieve the MX records for miek.nl.
func ExampleRR_MX() {
	config, _ := ClientConfigFromFile("/etc/resolv.conf")
	c := new(Client)
	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeMX)
	m.RecursionDesired = true
	r, err := c.Exchange(m, config.Servers[0]+":"+config.Port)
	if err != nil {
		return
	}
	if r.Rcode != RcodeSuccess {
		return
	}
	for _, a := range r.Answer {
		if mx, ok := a.(*RR_MX); ok {
			fmt.Printf("%s\n", mx.String())
		}
	}
}
