// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// An AS112 blackhole DNS server. Similar to the one found in evldns.
// Also see https://www.as112.net/

package main

import (
	"github.com/miekg/dns"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

const SOA string = "@ SOA prisoner.iana.org. hostmaster.root-servers.org. 2002040800 1800 900 0604800 604800"

func NewRR(s string) dns.RR { r, _ := dns.NewRR(s); return r }

var zones = map[string]dns.RR{
	"10.in-addr.arpa.":      NewRR("$ORIGIN 10.in-addr.arpa.\n" + SOA),
	"254.169.in-addr.arpa.": NewRR("$ORIGIN 254.169.in-addr.arpa.\n" + SOA),
	"168.192.in-addr.arpa.": NewRR("$ORIGIN 168.192.in-addr.arpa.\n" + SOA),
	"16.172.in-addr.arpa.":  NewRR("$ORIGIN 16.172.in-addr.arpa.\n" + SOA),
	"17.172.in-addr.arpa.":  NewRR("$ORIGIN 17.172.in-addr.arpa.\n" + SOA),
	"18.172.in-addr.arpa.":  NewRR("$ORIGIN 18.172.in-addr.arpa.\n" + SOA),
	"19.172.in-addr.arpa.":  NewRR("$ORIGIN 19.172.in-addr.arpa.\n" + SOA),
	"20.172.in-addr.arpa.":  NewRR("$ORIGIN 20.172.in-addr.arpa.\n" + SOA),
	"21.172.in-addr.arpa.":  NewRR("$ORIGIN 21.172.in-addr.arpa.\n" + SOA),
	"22.172.in-addr.arpa.":  NewRR("$ORIGIN 22.172.in-addr.arpa.\n" + SOA),
	"23.172.in-addr.arpa.":  NewRR("$ORIGIN 23.172.in-addr.arpa.\n" + SOA),
	"24.172.in-addr.arpa.":  NewRR("$ORIGIN 24.172.in-addr.arpa.\n" + SOA),
	"25.172.in-addr.arpa.":  NewRR("$ORIGIN 25.172.in-addr.arpa.\n" + SOA),
	"26.172.in-addr.arpa.":  NewRR("$ORIGIN 26.172.in-addr.arpa.\n" + SOA),
	"27.172.in-addr.arpa.":  NewRR("$ORIGIN 27.172.in-addr.arpa.\n" + SOA),
	"28.172.in-addr.arpa.":  NewRR("$ORIGIN 28.172.in-addr.arpa.\n" + SOA),
	"29.172.in-addr.arpa.":  NewRR("$ORIGIN 29.172.in-addr.arpa.\n" + SOA),
	"30.172.in-addr.arpa.":  NewRR("$ORIGIN 30.172.in-addr.arpa.\n" + SOA),
	"31.172.in-addr.arpa.":  NewRR("$ORIGIN 31.172.in-addr.arpa.\n" + SOA),
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU() * 4)
	for z, rr := range zones {
		rrx := rr.(*dns.SOA) // Needed to create the actual RR, and not an reference.
		dns.HandleFunc(z, func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			m.Ns = []dns.RR{rrx}
			w.WriteMsg(m)
		})
	}
	go func() {
		err := dns.ListenAndServe(":8053", "tcp", nil)
		if err != nil {
			log.Fatal("Failed to set tcp listener %s\n", err.Error())
		}
	}()
	go func() {
		err := dns.ListenAndServe(":8053", "udp", nil)
		if err != nil {
			log.Fatal("Failed to set udp listener %s\n", err.Error())
		}
	}()
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case s := <-sig:
			log.Fatalf("Signal (%d) received, stopping\n", s)
		}
	}
}
