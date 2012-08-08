package main

// TODO: locking, tsig (need key list to rewrap the queries)

import (
	"dns"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"
	"time"
)

var (
	listen  = flag.String("listen", ":8053", "set the listener address")
	server  = flag.String("server", ":53", "remote server address")
	flagttl = flag.Int("ttl", 30, "ttl (in seconds) for cached packets")
	flaglog = flag.Bool("log", false, "be more verbose")
	cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
)

func serve(w dns.ResponseWriter, r *dns.Msg, c *Cache) {
	switch {
	case r.IsNotify():
		if *flaglog {
			log.Printf("fks-shield: notify/update")
		}
		fallthrough
	case r.IsUpdate():
		client := new(dns.Client)
		if p, e := client.Exchange(r, *server); e == nil {
			w.Write(p)
		}
		return
	}
	if p := c.Find(r); p != nil {
		b := []byte{0, 0}
		dns.RawSetId(b, r.MsgHdr.Id)
		p = append(b, p...)
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
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	cache := NewCache()
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) { serve(w, r, cache) })

	// Only listen on UDP
	go func() {
		if err := dns.ListenAndServe(*listen, "udp", nil); err != nil {
			log.Fatalf("fks-shield: failed to setup %s %s", *listen, "udp")
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
	signal.Notify(sig, os.Interrupt)

forever:
	for {
		select {
		case <-sig:
			log.Printf("fks-shield: signal received, stopping")
			break forever
		}
	}
}
