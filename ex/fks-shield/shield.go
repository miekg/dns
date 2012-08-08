package main

// TODO: locking

import (
	"dns"
	"flag"
	"log"
	"os"
	"time"
)

var (
	listen  = flag.String("listen", "127.0.0.1:8053", "set the listener address")
	server  = flag.String("server", "127.0.0.1:53", "remote server address")
	flaglog = flag.Bool("log", false, "be more verbose")
)

func serve(w dns.ResponseWriter, r *dns.Msg, c *Cache) {
	// only do queries not dynamic updates
	if *flaglog {
		log.Printf("fks-shield: query")
	}
	if p := c.Find(r); p != nil {
		dns.RawSetId(p, r.MsgHdr.Id)
		w.WriteBuf(p)
		return
	}
	// Cache miss
	client := new(dns.Client)
	if p, e := client.Exchange(r, *server); e == nil {
		// TODO(mg): If r has edns0 and p has not we create a mismatch here
		w.Write(p)
		c.Insert(p)
		return
	} else {
		log.Printf("fks-shield: failed to get answer " + e.Error())
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.Write(m)
	}
}

func main() {
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()

	cache := NewCache()
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) { serve(w, r, cache) })

	// Only listen on UDP
	go func() {
		if err := dns.ListenAndServe(*listen, "udp", nil); err != nil {
			log.Fatal("fks-shield: failed to setup %s %s", *listen, "udp")
		}
	}()
	go func() {
		for {
			// Every 10 sec run the cache cleaner
			time.Sleep(10 * 1e9)
			cache.Evict()
		}
	}()

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
