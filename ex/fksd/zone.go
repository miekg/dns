package main

import (
	"dns"
	"errors"
	"log"
	"os"
)

// ReadZone reads a zone and adds it.
func (c *Config) ReadZone(origin, file string) error {
	z := dns.NewZone(origin)
	if z == nil {
		return errors.New("fks: failed to open zone file")
	}
	f, e := os.Open(file)
	if e != nil {
		return e
	}
	for rr := range dns.ParseZone(f, origin, file) {
		if rr.Error == nil {
			z.Insert(rr.RR)
		} else {
			log.Printf("fks: failed to parse: %s\n", rr.Error.Error())
		}
	}
	c.Zones[origin] = z
	return nil
}
