/* 
 * Funkensturm, a versatile DNS proxy
 * Miek Gieben <miek@miek.nl> (c) 2011
 * GPLv2
 */

package main

import (
	"dns"
	"flag"
	"log"
	"os"
)

func serve(w dns.ResponseWriter, req *dns.Msg) {

}

func listenAndServe(add, net string) {
	if err := dns.ListenAndServe(add, net, nil); err != nil {
		log.Printf("fks-shield: failed to setup:", net, add)
	}
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8053", "set the listener address")
	//server := flag.String("server", "127.0.0.1:53", "remote server address(es), seperate with commas")
	//verbose := flag.Bool("verbose", false, "Print packet as it flows through")
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()

	dns.HandleFunc(".", serve)
	go listenAndServe(*listen, "tcp")
	go listenAndServe(*listen, "udp")

	sig := make(chan os.Signal)
forever:
	for {
		select {
		case <-sig:
			log.Printf("fks-shield: signal received, stopping")
			break forever
		}
	}
}
