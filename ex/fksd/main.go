package main

import (
	"dns"
	"flag"
	"log"
	"os"
	"strings"
)

var (
	flaglog   = flag.Bool("log", false, "log incoming queries")
	superuser = flag.String("user", "root", "username to use for the superuser")
	superkey  = flag.String("key", "c3R1cGlk", "base64 tsig key for superuser authentication")
)

func main() {
	flag.Parse()
	conf := NewConfig()
	*superuser = strings.ToLower(*superuser)
	conf.Tsigs[dns.Fqdn(*superuser)] = *superkey
	conf.Rights[*superuser] = R_LIST | R_WRITE | R_DROP | R_USER // *all* of them

	go func() {
		err := dns.ListenAndServe(":1053", "udp", nil)
		if err != nil {
			log.Fatal("fksd: could not start server listener: %s", err.Error())
		}
	}()
	go func() {
		err := dns.ListenAndServeTsig(":8053", "tcp", nil, conf.Tsigs)
		if err != nil {
			log.Fatal("fksd: could not start config listener: %s", err.Error())
		}
	}()
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
