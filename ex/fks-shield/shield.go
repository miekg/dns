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

var (
	listen  = flag.String("listen", "127.0.0.1:8053", "set the listener address")
	server  = flag.String("server", "127.0.0.1:53", "remote server address(es), seperate with commas")
	verbose = flag.Bool("verbose", false, "be more verbose")
)

func serve(w dns.ResponseWriter, r *dns.Msg, c *Cache) {
	if p := c.Find(r); p != nil {
		dns.RawSetId(p, r.MsgHdr.Id)
		w.WriteBuf(p)
		return
	}
	// Cache miss
	client := new(dns.Client)
	if p, e := client.Exchange(r, *server); e == nil {
		if *verbose {
			log.Printf("fks-shield: cache miss")
		}
		// TODO(mg): If r has edns0 and p has not we create a mismatch here
		w.Write(p)
		c.Insert(p)
		return
	} else {
		log.Printf("fks-shield: failed to get answer " + e.Error())
		// w.Write(SERFVAIL)
	}
}

func listenAndServe(add, net string) {
	if err := dns.ListenAndServe(add, net, nil); err != nil {
		log.Fatal("fks-shield: failed to setup %s %s", net, add)
	}
}

func main() {
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()

	cache := NewCache()

	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) { serve(w, r, cache) })

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
