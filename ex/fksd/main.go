package main

import (
	"dns"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
)

var (
	flaglog   = flag.Bool("log", false, "log incoming queries")
	superuser = flag.String("user", "root", "username to use for the superuser")
	superkey  = flag.String("key", "c3R1cGlk", "base64 tsig key for superuser authentication")
)

func main() {
	flag.Parse()
	*superuser = strings.ToLower(*superuser)
	conf := NewConfig()
	conf.Rights[*superuser] = R_LIST | R_WRITE | R_DROP | R_USER // *all* of them

	go func() {
		err := dns.ListenAndServe(":1053", "udp", nil)
		if err != nil {
			log.Fatal("fksd: could not start server listener: %s", err.Error())
		}
	}()
	go func() {
		conf.Server = &dns.Server{Addr: ":1053", Net: "tcp", TsigSecret: map[string]string{dns.Fqdn(*superuser): *superkey}}
		err := conf.Server.ListenAndServe()
		if err != nil {
			log.Fatal("fksd: could not start config listener: %s", err.Error())
		}
	}()

	// Yes, we HIJACK zone. ... not sure on how to make this "private"
	dns.HandleFunc("ZONE.", func(w dns.ResponseWriter, req *dns.Msg) { config(w, req, conf) })
	// Gasp!! And USER.
	dns.HandleFunc("USER.", func(w dns.ResponseWriter, req *dns.Msg) { config(w, req, conf) })

	sig := make(chan os.Signal)
	signal.Notify(sig, os.Interrupt)
forever:
	for {
		select {
		case <-sig:
			logPrintf("signal received, stopping")
			break forever
		}
	}
}
