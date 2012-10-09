// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Extended and bugfixes by Miek Gieben. Copyright 2010-2012.

// Package dns implements a full featured interface to the Domain Name System.
// Server- and client-side programming is supported.
// The package allows complete control over what is send out to the DNS. The package
// API follows the less-is-more principle, by presenting a small, clean interface.
//
// The package dns supports (asynchronous) querying/replying, incoming/outgoing AXFR/IXFR, 
// TSIG, EDNS0, dynamic updates, notifies and DNSSEC validation/signing.
// Note that domain names MUST be fully qualified, before sending them, unqualified
// names in a message will result in a packing failure.
//
// Resource records are native types. They are not stored in wire format.
// Basic usage pattern for creating a new resource record:
//
//      r := new(dns.RR_MX)
//      r.Hdr = dns.RR_Header{Name: "miek.nl.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 3600}
//      r.Pref = 10
//      r.Mx = "mx.miek.nl."
//
// Or directly from a string:
//
//      mx, err := dns.NewRR("miek.nl. 3600 IN MX 10 mx.miek.nl.")
//
// Or when the default TTL (3600) and class (IN) suit you:
//
//      mx, err := dns.NewRR("miek.nl. MX 10 mx.miek.nl.")
//
// Or even:
//
//      mx, err := dns.NewRR("$ORIGIN nl.\nmiek 1H IN MX 10 mx.miek")
//
// In the DNS messages are exchanged, these messages contain resource
// records (sets).  Use pattern for creating a message:
//
//      m := dns.new(Msg)
//      m.SetQuestion("miek.nl.", dns.TypeMX)
//
// Or when not certain if the domain name is fully qualified:
//
//	m.SetQuestion(dns.Fqdn("miek.nl"), dns.TypeMX)
//
// The message m is now a message with the question section set to ask
// the MX records for the miek.nl. zone.
//
// The following is slightly more verbose, but more flexible:
//
//      m1 := new(dns.Msg)
//      m1.Id = Id()
//      m1.RecursionDesired = true
//      m1.Question = make([]Question, 1)
//      m1.Question[0] = dns.Question{"miek.nl.", dns.TypeMX, dns.ClassINET}
//
// After creating a message it can be send.
// Basic use pattern for synchronous querying the DNS at a
// server configured on 127.0.0.1 and port 53:
//
//      c := new(Client)
//      in, err := c.Exchange(m1, "127.0.0.1:53")
//
// An asynchronous query is also possible, see client.Do and client.DoRtt.
//
// From a birds eye view a dns message consists out of four sections.
// The question section: in.Question, the answer section: in.Answer,
// the authority section: in.Ns and the additional section: in.Extra.
//
// Each of these sections (except the Question section) contain a []RR. Basic
// use pattern for accessing the rdata of a TXT RR as the first RR in 
// the Answer section:
//
//	if t, ok := in.Answer[0].(*RR_TXT); ok {
//		// do something with t.Txt
//	}
package dns

import (
	"net"
	"strconv"
)

const (
	year68         = 1 << 31 // For RFC1982 (Serial Arithmetic) calculations in 32 bits.
	DefaultMsgSize = 4096    // Standard default for larger than 512 packets.
	udpMsgSize     = 512     // Default buffer size for servers receiving UDP packets.
	MaxMsgSize     = 65536   // Largest possible DNS packet.
	defaultTtl     = 3600    // Default TTL.
)

// Error represents a DNS error
type Error struct {
	Err     string
	Name    string
	Server  net.Addr
	Timeout bool
}

func (e *Error) Error() string {
	if e == nil {
		return "dns: <nil>"
	}
	if e.Name == "" {
		return "dns: " + e.Err
	}
	return "dns: " + e.Name + ": " + e.Err

}

// An RR represents a resource record.
type RR interface {
	// Header returns the header of an resource record. The header contains
	// everything up to the rdata.
	Header() *RR_Header
	// String returns the text representation of the resource record.
	String() string
	// Len returns the length (in octects) of the uncompressed RR in wire format.
	Len() int
	// Copy returns a copy of the RR
	Copy() RR
}

// DNS resource records.
// There are many types of RRs,
// but they all share the same header.
type RR_Header struct {
	Name     string `dns:"cdomain-name"`
	Rrtype   uint16
	Class    uint16
	Ttl      uint32
	Rdlength uint16 // length of data after header
}

func (h *RR_Header) Header() *RR_Header {
	return h
}

func (h *RR_Header) CopyHeader() *RR_Header {
	r := new(RR_Header)
	r.Name = h.Name
	r.Rrtype = h.Rrtype
	r.Class = h.Class
	r.Ttl = h.Ttl
	r.Rdlength = h.Rdlength
	return r
}

// Just to imlement the RR interface
func (h *RR_Header) Copy() RR {
	return nil
}

func (h *RR_Header) String() string {
	var s string

	if h.Rrtype == TypeOPT {
		s = ";"
		// and maybe other things
	}

	if len(h.Name) == 0 {
		s += ".\t"
	} else {
		s += h.Name + "\t"
	}
	s = s + strconv.FormatInt(int64(h.Ttl), 10) + "\t"

	if _, ok := Class_str[h.Class]; ok {
		s += Class_str[h.Class] + "\t"
	} else {
		s += "CLASS" + strconv.Itoa(int(h.Class)) + "\t"
	}

	if _, ok := Rr_str[h.Rrtype]; ok {
		s += Rr_str[h.Rrtype] + "\t"
	} else {
		s += "TYPE" + strconv.Itoa(int(h.Rrtype)) + "\t"
	}
	return s
}

func (h *RR_Header) Len() int {
	l := len(h.Name) + 1
	l += 10 // rrtype(2) + class(2) + ttl(4) + rdlength(2)
	return l
}

// find best matching pattern for zone
func zoneMatch(pattern, zone string) (ok bool) {
	if len(pattern) == 0 {
		return
	}
	if len(zone) == 0 {
		zone = "."
	}
	// pattern = Fqdn(pattern) // should already be a fqdn
	zone = Fqdn(zone)
	i := 0
	for {
		ok = pattern[len(pattern)-1-i] == zone[len(zone)-1-i]
		i++

		if !ok {
			break
		}
		if len(pattern)-1-i < 0 || len(zone)-1-i < 0 {
			break
		}

	}
	return
}
