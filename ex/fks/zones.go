package main

import (
	"dns"
	"errors"
	"os"
)

// Read a zone and add it.
func addZone(zones map[string]*dns.Zone, origin, file string) error {
	origin = dns.Fqdn(origin)
	z1 := dns.NewZone(origin)
	if z1 == nil {
		return errors.New("boe")
	}
	f, e := os.Open(file)
	if e != nil {
		return e
	}
	for rr := range dns.ParseZone(f, origin, file) {
		// TODO(mg): blab something about the error?
		if rr.Error == nil {
			z1.Insert(rr.RR)
		}
	}
	zones[origin] = z1
	return nil
}
