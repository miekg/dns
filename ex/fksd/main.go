package main

import (
	"dns"
	"flag"
	"log"
	"os"
)

var (
	z = flag.String("zone", "", "zonefile to read")
	o = flag.String("origin", "", "origin of the zone")
	l = flag.Bool("log", false, "log incoming queries")
)

func main() {
	flag.Parse()
	if *z == "" {
		log.Fatal("fksd: no zone")
	}
	if *o == "" {
		log.Fatal("fksd: origin")
	}
	Z := make(map[string]*dns.Zone)
	if e := addZone(Z, *o, *z); e != nil {
		log.Fatal("fksd: %s\n", e.Error())
	}
	if e := addZone(Z, "nl.", "z/nl.db"); e != nil {
		log.Fatal("fksd: %s\n", e.Error())
	}

	dns.HandleFunc(*o, func(w dns.ResponseWriter, req *dns.Msg) { serve(w, req, Z[dns.Fqdn(*o)]) })
	dns.HandleFunc("nl.", func(w dns.ResponseWriter, req *dns.Msg) { serve(w, req, Z["nl."]) })

	go func() {
		err := dns.ListenAndServe(":8053", "udp", nil)
		if err != nil {
			log.Fatal("fksd: could not start")
		}
	}()
	sig := make(chan os.Signal)
forever:
	for {
		select {
		case <-sig:
			log.Printf("fksd: signal received, stopping\n")
			break forever
		}
	}
}
