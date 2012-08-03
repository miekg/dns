package main

import (
	"dns"
	"errors"
	"flag"
	"log"
	"os"
)

var (
	z = flag.String("zone", "", "zonefile to read")
	o = flag.String("origin", "", "origin of the zone")
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

// zone origin file
func main() {
	flag.Parse()
	if *z == "" {
		log.Fatal("no zone")
	}
	if *o == "" {
		log.Fatal("no origin")
	}
	Z := make(map[string]*dns.Zone)
	addZone(Z, *o, *z)
	dns.HandleFunc(*o, func(w dns.ResponseWriter, req *dns.Msg) { serve(w, req, Z[*o]) })
	go func() {
		err := dns.ListenAndServe(":8053", "udp", nil)
		if err != nil {
			log.Fatal("Could not start")
		}
	}()
	sig := make(chan os.Signal)
forever:
	for {
		select {
		case <-sig:
			log.Printf("Signal received, stopping\n")
			break forever
		}
	}
}
