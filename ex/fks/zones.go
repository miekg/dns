package main

import (
	"dns"
	"errors"
	"flag"
	"log"
	"os"
	"radix"
)

var (
	z   = flag.String("zone", "", "zonefile to read")
	o = flag.String("origin", "", "origin of the zone")
)

// Zones holds all the zones we have. Its only holds
// the zone's name and nothing else.
type Zones struct {
	*radix.Radix
}

// Read a zone and add it.
func (z *Zones) addZone(origin, file string) error {
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
	z.Radix.Insert(origin, z1)
	return nil
}

// zone origin file
func main() {
	flag.Parse()
	if *z == "" {
		log.Fatal("no zone")
	}
	if *o == "" {
		log.Fatal("no origin")
	}
	Z := new(Zones)
	Z.addZone(*o, *z)
	dns.HandleFunc(*o, func(w dns.ResponseWriter, req *dns.Msg) { serve(w, req, Z) })
	// NX domain??
}
