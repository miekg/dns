package main

import (
	"dns"
	"errors"
	"log"
	"os"
)

// Read a zone and add it.
func addZone(zones map[string]*dns.Zone, origin, file string) error {
	origin = dns.Fqdn(origin)
	z1 := dns.NewZone(origin)
	if z1 == nil {
		return errors.New("fks: failed to open zone file")
	}
	f, e := os.Open(file)
	if e != nil {
		return e
	}
	for rr := range dns.ParseZone(f, origin, file) {
		if rr.Error == nil {
			z1.Insert(rr.RR)
		} else {
			log.Printf("fks: failed to parse: %s\n", rr.Error.Error())
		}
	}
	zones[origin] = z1
	return nil
}
