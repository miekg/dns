// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Extended and bugfixes by Miek Gieben.

// DOMAIN NAME SYSTEM
//
// Package dns implements a full featured interface to the Domain Name System.
// The package allows complete control over what is send out to the DNS. 
//
// Resource records are native types. They are not stored in wire format.
// Basic usage pattern for creating a new resource record:
//
//      r := new(RR_TXT)
//      r.Hdr = RR_Header{Name: "a.miek.nl.", Rrtype: TypeTXT, Class: ClassINET, Ttl: 3600}
//      r.TXT = "This is the content of the TXT record"
//
// Or directly from a string:
//
//      mx := NewRR("miek.nl. IN MX 10 mx.miek.nl.")
// 
// The package dns supports (async) querying/replying, incoming/outgoing Axfr/Ixfr, 
// TSIG, EDNS0, dynamic updates, notifies and DNSSEC validation/signing.
//
// In the DNS messages are exchanged. Use pattern for creating one:
//
//      m := new(Msg)
//      m.SetQuestion("miek.nl.", TypeMX)
//
// The message m is now a message with the question section set to ask
// the MX records for the miek.nl. zone.
//
// The following is slightly more verbose, but more flexible:
//
//      m1 := new(Msg)
//      m1.MsgHdr.Id = Id()
//      m1.MsgHdr.RecursionDesired = false
//      m1.Question = make([]Question, 1)
//      m1.Question[0] = Question{"miek.nl.", TypeMX, ClassINET}
//
// After creating a message it can be send.
// Basic use pattern for synchronous querying the DNS. We are
// sending the message 'm' to the server 127.0.0.1 on port 53 and
// waiting for the reply.
//
//      c := dns.NewClient()
//      // c.Net = "tcp" // If you want to use TCP
//      in := c.Exchange(m, "127.0.0.1:53")
//
// An asynchronous query is also possible. The Basic use pattern is: TODO(mg)
package dns

import (
	"net"
	"strconv"
)

const (
	Year68         = 2 << (32 - 1) // For RFC1982 (Serial Arithmetic) calculations in 32 bits.
	DefaultMsgSize = 4096          // A standard default for larger than 512 packets.
	MaxMsgSize     = 65536         // Largest possible DNS packet.
	DefaultTtl     = 3600          // Default TTL.
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
		return "<nil>"
	}
	return e.Err
}

type RR interface {
	Header() *RR_Header
	String() string
}

// An RRset is a slice of RRs.
type RRset []RR

func NewRRset() RRset {
	s := make([]RR, 0)
	return s
}

func (s RRset) String() string {
	str := ""
	for _, r := range s {
		str += r.String() + "\n"
	}
	return str
}

// Pop removes the last pushed RR from the RRset. Returns nil
// when there is nothing to remove.
func (s *RRset) Pop() RR {
	if len(*s) == 0 {
		return nil
	}
	// Pop and remove the entry
	r := (*s)[len(*s)-1]
	*s = (*s)[:len(*s)-1]
	return r
}

// Push pushes the RR r to the RRset.
func (s *RRset) Push(r RR) bool {
	if len(*s) == 0 {
		*s = append(*s, r)
		return true
	}
	// For RRSIGs this is not true (RFC???)
	// Don't make it a failure if this happens
	//	if (*s)[0].Header().Ttl != r.Header().Ttl {
	//                return false
	//        }
	if (*s)[0].Header().Name != r.Header().Name {
		return false
	}
	if (*s)[0].Header().Class != r.Header().Class {
		return false
	}
	*s = append(*s, r)
	return true
}

// Ok checks if the RRSet is RFC 2181 compliant.
func (s RRset) Ok() bool {
	ttl := s[0].Header().Ttl
	name := s[0].Header().Name
	class := s[0].Header().Class
	for _, rr := range s[1:] {
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

// Exchange is used in communicating with the resolver.
type Exchange struct {
	Request *Msg  // The question sent.
	Reply   *Msg  // The answer to the question that was sent.
	Error   error // If something went wrong, this contains the error.
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

func zoneMatch(pattern, zone string) (ok bool) {
	if len(pattern) == 0 {
		return
	}
	if pattern[len(pattern)-1] != '.' {
		pattern += "."
	}
	if zone[len(zone)-1] != '.' {
		zone += "."
	}
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

// DnameLength returns the length of a packed dname.
func DomainNameLength(s string) int { // TODO better name
	// Special case for '.'
	if s == "." {
		return 1
	}

	// Add trailing dot to canonicalize name.
	if n := len(s); n == 0 || s[n-1] != '.' {
		return n + 1
	} else {
		return n + 1
	}
	panic("not reached")
	return 0
}
