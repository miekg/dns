// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// An AS212 blackhole DNS server. Similar to the one found in evldns.
// Also see https://www.as112.net/

package main

import (
	"github.com/miekg/dns"
)

const SOA string = "@ SOA prisoner.iana.org. hostmaster.root-servers.org. 2002040800 1800 900 0604800 604800"

var zones = map[string]dns.RR{
	"10.in-addr.arpa":      NewRR("$ORIGIN 10.in-addr.arpa.\n" + SOA),
	"254.169.in-addr.arpa": NewRR("$ORIGIN 254.169.in-addr.arpa.\n" + SOA),
	"168.192.in-addr.arpa": NewRR("$ORIGIN 168.192.in-addr.arpa.\n" + SOA),
	"16.172.in-addr.arpa":  NewRR("$ORIGIN 16.172.in-addr.arpa.\n" + SOA),
	"17.172.in-addr.arpa":  NewRR("$ORIGIN 17.172.in-addr.arpa.\n" + SOA),
	"18.172.in-addr.arpa":  NewRR("$ORIGIN 18.172.in-addr.arpa.\n" + SOA),
	"19.172.in-addr.arpa":  NewRR("$ORIGIN 19.172.in-addr.arpa.\n" + SOA),
	"20.172.in-addr.arpa":  NewRR("$ORIGIN 20.172.in-addr.arpa.\n" + SOA),
	"21.172.in-addr.arpa":  NewRR("$ORIGIN 21.172.in-addr.arpa.\n" + SOA),
	"22.172.in-addr.arpa":  NewRR("$ORIGIN 22.172.in-addr.arpa.\n" + SOA),
	"23.172.in-addr.arpa":  NewRR("$ORIGIN 23.172.in-addr.arpa.\n" + SOA),
	"24.172.in-addr.arpa":  NewRR("$ORIGIN 24.172.in-addr.arpa.\n" + SOA),
	"25.172.in-addr.arpa":  NewRR("$ORIGIN 25.172.in-addr.arpa.\n" + SOA),
	"26.172.in-addr.arpa":  NewRR("$ORIGIN 26.172.in-addr.arpa.\n" + SOA),
	"27.172.in-addr.arpa":  NewRR("$ORIGIN 27.172.in-addr.arpa.\n" + SOA),
	"28.172.in-addr.arpa":  NewRR("$ORIGIN 28.172.in-addr.arpa.\n" + SOA),
	"29.172.in-addr.arpa":  NewRR("$ORIGIN 29.172.in-addr.arpa.\n" + SOA),
	"30.172.in-addr.arpa":  NewRR("$ORIGIN 30.172.in-addr.arpa.\n" + SOA),
	"31.172.in-addr.arpa":  NewRR("$ORIGIN 31.172.in-addr.arpa.\n" + SOA),
}

func NewRR(s string) dns.RR {
	r, _ := dns.NewRR(s)
	return r
}

func as212Handler(w dns.ResponseWriter, r *dns.Msg) {}
func main()                                         {}
