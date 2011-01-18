// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Extended and bugfixes by Miek Gieben

// Supported RFCs and features include:
// * 1034/1035  - DNS standard
// * 1982 - Serial Arithmetic
// * 1876 - LOC record (incomplete)
// * 1995 - IXFR
// * 1996 - DNS notify
// * 2181 - RRset definition
// * 2537 - RSAMD5 DNS keys
// * 2065 - DNSSEC (updated in later RFCs)
// * 2671 - EDNS
// * 2782 - SRV record
// * 2845 - TSIG
// * 2915 - NAPTR record 
// * 3110 - RSASHA1 DNS keys
// * 3225 - DO bit (DNSSEC OK)
// * 4033/4034/4035 - DNSSEC + validation functions
// * 4255 - SSHFP record
// * 5011 - NSID 
// * 5936 - AXFR
// * IP6 support

// Package dns implements a full featured interface to the DNS.
// The package allows full control over what is send out to the DNS. All RR types are converted
// to Go types.
//
package dns

import (
	"strconv"
)

// For RFC1982 (Serial Arithmetic) calculations.
const Year68 = 2 << (32 - 1)

// Error represents a DNS error
type Error struct {
	Error   string
	Name    string
	Server  string
	Timeout bool
}

func (e *Error) String() string {
	if e == nil {
		return "<nil>"
	}
	return e.Error
}

// Meta data when querying
type Meta struct {
	QLen       int   // query length in bytes
	RLen       int   // reply length in bytes
	QueryStart int64 // start of query in nanoseconds epoch
	QueryEnd   int64 // end of query in nanosecond epoch
}

func (m *Meta) String() string {
	s := ";; Query time: " + strconv.Itoa(int(m.QueryEnd-m.QueryStart)) + " nsec"
	s += "\n;; MSG SIZE  rcvd: " + strconv.Itoa(m.RLen) + ", sent: " + strconv.Itoa(m.QLen)
	rf := float32(m.RLen)
	qf := float32(m.QLen)
        if qf != 0 {
	        s += " (" + strconv.Ftoa32(rf/qf, 'f', 2) + ":1)"
        }
	// WHEN??
	return s
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
	s = s + Class_str[h.Class] + "\t"
	s = s + Rr_str[h.Rrtype] + "\t"
	return s
}

// Return the number of labels in a domain name
func LabelCount(a string) (c uint8) {
	for _, v := range a {
		if v == '.' {
			c++
		}
	}
	return
}
