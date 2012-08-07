package main

import (
	"dns"
	"flag"
	"log"
	"os"
)

var (
	flaglog   = flag.Bool("log", false, "log incoming queries")
	superuser = flag.String("user", "root", "username to use for the superuser")
	superkey  = flag.String("key", dns.HmacSHA1+":c3R1cGlk", "tsig [hmac:base64] key for superuser authentication")
)

func main() {
	flag.Parse()
	conf := NewConfig()
	go func() {
		err := dns.ListenAndServe(":1053", "udp", nil)
		if err != nil {
			log.Fatal("fksd: could not start server listener: %s", err.Error())
		}
	}()
	go func() {
		err := dns.ListenAndServe(":8053", "tcp", nil)
		if err != nil {
			log.Fatal("fksd: could not start config listener: %s", err.Error())
		}
	}()
	conf.Users[*superuser] = true
	conf.Tsigs[*superuser] = superkey
	conf.Rights[*superuser] = R_LIST | R_WRITE | R_DROP | R_USER // *all* of them
	// Yes, we HIJACK zone. ... not sure on how to make this "private"
	dns.HandleFunc("ZONE.", func(w dns.ResponseWriter, req *dns.Msg) { config(w, req, conf) })
	// Gasp!! And USER.
	dns.HandleFunc("USER.", func(w dns.ResponseWriter, req *dns.Msg) { config(w, req, conf) })

	sig := make(chan os.Signal)
forever:
	for {
		select {
		case <-sig:
			logPrintf("signal received, stopping")
			break forever
		}
	}
}
