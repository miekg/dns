package main

import (
	"dns"
	"flag"
	"log"
	"os"
)

var (
	l = flag.Bool("log", false, "log incoming queries")
)

func main() {
	flag.Parse()
	conf := NewConfig()
	go func() {
		err := dns.ListenAndServe(":8053", "udp", nil)
		if err != nil {
			log.Fatal("fksd: could not start config listener")
		}
	}()
	go func() {
		err := dns.ListenAndServe(":5353", "udp", nil)
		if err != nil {
			log.Fatal("fksd: could not start server listener")
		}
	}()
	// Yes, we HIJACK zone. ... not sure on how to make this "private"
	dns.HandleFunc("zone.", func(w dns.ResponseWriter, req *dns.Msg) { config(w, req, conf) })

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
