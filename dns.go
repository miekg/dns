// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Extended and bugfixes by Miek Gieben.

// Package dns implements a full featured interface to the DNS.
// The package allows complete control over what is send out to the DNS. 
//
// Resource records are native types. They are not stored in wire format.
// Basic usage pattern for creating a new resource record:
//
//         r := new(RR_TXT)
//         r.Hdr = RR_Header{Name: "a.miek.nl", Rrtype: TypeTXT, Class: ClassINET, Ttl: 3600}
//         r.TXT = "This is the content of the TXT record"
// 
// The package dns supports (async) querying/replying, incoming/outgoing Axfr/Ixfr, 
// TSIG, EDNS0, dynamic updates, notifies and DNSSEC validation/signing.
//
// In the DNS messages are exchanged. Use pattern for creating one:
//
//      m := new(Msg)
//      m.SetQuestion("miek.nl.", TypeMX)
//
//
// Or slightly more verbose and flexible:
//
//      m1 := new(Msg)
//      m1.MsgHdr.Id = Id()
//      m1.MsgHdr.RecursionDesired = false
//      m1.Question = make([]Question, 1)
//      m1.Question[0] = Question{"miek.nl", TypeDNSKEY, ClassINET}
//
//
// Basic use pattern for synchronous querying of the DNS
//
//      c := dns.NewClient()
//      // c.Net = "tcp" // If you want to use TCP
//      in := c.Exchange(m, "127.0.0.1:53")
//
package dns

import (
	"net"
	"strconv"
)

const (
	Year68         = 2 << (32 - 1) // For RFC1982 (Serial Arithmetic) calculations in 32 bits.
	DefaultMsgSize = 4096          // A standard default for larger than 512 packets.
	MaxMsgSize     = 65536         // Largest possible DNS packet.
	DefaultTTL     = 3600          // Default TTL.
)

// Error represents a DNS error
type Error struct {
	Error   string
	Name    string
	Server  net.Addr
	Timeout bool
}

func (e *Error) String() string {
	if e == nil {
		return "<nil>"
	}
	return e.Error
}

type RR interface {
	Header() *RR_Header
	String() string
}

// An RRset is a slice of RRs.
type RRset []RR

func (r RRset) Len() int           { return len(r) }
func (r RRset) Less(i, j int) bool { return r[i].Header().Name < r[j].Header().Name }
func (r RRset) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }

// Check if the RRset is RFC 2181 compliant
func (r RRset) Ok() bool {
	ttl := r[0].Header().Ttl
	name := r[0].Header().Name
	class := r[0].Header().Class
	for _, rr := range r[1:] {
		if rr.Header().Ttl != ttl {
			return false
		}
		if rr.Header().Name != name {
			return false
		}
		if rr.Header().Class != class {
			return false
		}
	}
	return true
}

// DNS resource records.
// There are many types of messages,
// but they all share the same header.
type RR_Header struct {
	Name     string "domain-name"
	Rrtype   uint16
	Class    uint16
	Ttl      uint32
	Rdlength uint16 // length of data after header
}

func (h *RR_Header) Header() *RR_Header {
	return h
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
	s = s + strconv.Itoa(int(h.Ttl)) + "\t"

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

// Return the number of labels in a domain name.
// Need to add these kind of function in a structured way. TODO(mg)
func LabelCount(a string) (c uint8) {
	// walk the string and count the dots
	// except when it is escaped
	esc := false
	for _, v := range a {
		switch v {
		case '.':
			if esc {
				esc = !esc
				continue
			}
			c++
		case '\\':
			esc = true
		}
	}
	return
}
