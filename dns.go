// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Extended and bugfixes by Miek Gieben

// Package dns implements a full featured interface to the DNS.
// Supported RFCs and features include:
// * 1034/1035  - DNS standard
// * 1982 - Serial Arithmetic
// * 1876 - LOC record (incomplete)
// * 1995 - IXFR
// * 1996 - DNS notify
// * 2537 - RSAMD5 DNS keys
// * 2671 - EDNS
// * 2845 - TSIG
// * 2915 - NAPTR record (incomplete)
// * 3110 - RSASHA1 DNS keys
// * 3225 - DO bit (DNSSEC OK)
// * 4033/4034/4035 - DNSSEC + validation functions
// * 5011 - NSID
// * 5936 - AXFR
// * IP6 support
//
// The package allows full control over what is send out to the DNS.
//
package dns

import (
	"strconv"
        "os"
        "net"
)

const Year68 = 2 << (32 - 1)

type Error struct {
	Error     string
	Name      string
	Server    string
        Timeout   bool
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

func SendTCP(c net.Conn, m []byte) os.Error {
        l := make([]byte, 2)
        l[0] = byte(len(m) >> 8)
        l[1] = byte(len(m))
        // First we send the length
        _, err := c.Write(l)
        if err != nil {
                return err
        }
        // And the the message
        _, err = c.Write(m)
        if err != nil {
                return err
        }
        return nil
}

func RecvTCP(c net.Conn) ([]byte, os.Error) {
        l := make([]byte, 2) // receiver length
        // The server replies with two bytes length
        _, err := c.Read(l)
        if err != nil {
                return nil,err
        }
        length := uint16(l[0])<<8 | uint16(l[1])
        if length == 0 {
                return nil, &Error{Error: "received nil msg length", Server: c.RemoteAddr().String()}
        }
        m := make([]byte, length)
        n, cerr := c.Read(m)
        if cerr != nil {
                return nil, cerr
        }
        i := n
        if i < int(length) {
                n, err = c.Read(m[i:])
                if err != nil {
                        return nil, err
                }
                i += n
        }
        return m, nil
}

// Or expose the pack/unpack functions??
// These were created for dnssec.go, but now that
// that package is included again in dns, they are
// not really needed. These will be removed asap.
// Return the wiredata of rdata portion of a RR.
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

// Return the wiredata of a domainname (sans compressions).
func WireDomainName(s string) ([]byte, bool) {
	buf := make([]byte, 255)
	off, ok := packDomainName(s, buf, 0)
	if !ok {
		return nil, ok
	}
	buf = buf[:off]
	return buf, ok
}

// Return the wiredata of a complete Resource Record.
func WireRR(r RR) ([]byte, bool) {
	buf := make([]byte, 4096)
	off, ok := packRR(r, buf, 0)
	if !ok {
		return nil, false
	}
	buf = buf[:off]
	return buf, ok
}
