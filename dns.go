// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Extended and bugfixes by Miek Gieben

// Package dns implements a full featured interface to the DNS.
// Supported RFCs and features include:
// * 1034/1035
// * 2671 - EDNS
// * 4033/4034/4035 - DNSSEC + validation functions
// * 1982 - Serial Arithmetic
// * IP6 support
// The package allows full control over what is send out to the DNS.
//
// Basic usage pattern for creating new Resource Record:
//
// r := new(RR_TXT)
// r.TXT = "This is the content of the TXT record"
// r.Hdr = RR_Header{Name: "a.miek.nl", Rrtype: TypeTXT, Class: ClassINET, Ttl: 3600}
//
package dns

import ( "strconv")

const Year68 = 2 << (32 - 1)

type RR interface {
        Header() *RR_Header
        String() string
}

// An RRset is a slice of RRs.
type RRset []RR

func (r RRset) Len() int           { return len(r) }
func (r RRset) Less(i, j int) bool { return r[i].Header().Name < r[j].Header().Name }
func (r RRset) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }

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
        s = s + class_str[h.Class] + "\t"
        s = s + rr_str[h.Rrtype] + "\t"
        return s
}

// Or expose the pack/unpack functions??

// Return the rdata of the RR in wireform.
func WireRdata(r RR) ([]byte, bool) {
        buf := make([]byte, 4096) // Too large, need to FIX TODO(mg)
        off1, ok := packRR(r, buf, 0)
        if !ok {
                return nil, false
        }
        start := off1 - int(r.Header().Rdlength)
        end := start + int(r.Header().Rdlength)
        buf = buf[start:end]
        return buf, true
}

// Return the wiredata of a domainname (sans compressions)
func WireDomainName(s string) ([]byte, bool) {
        buf := make([]byte, 255)
        off, ok := packDomainName(s, buf, 0)
        if !ok {
                return nil, ok
        }
        buf = buf[:off]
        return buf, ok
}

func WireRR(r RR) ([]byte, bool) {
        buf := make([]byte, 4096)
        off, ok := packRR(r, buf, 0)
        if !ok {
                return nil, false
        }
        buf = buf[:off]
        return buf, ok
}
