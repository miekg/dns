// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Extended and bugfixes by Miek Gieben

// Package dns implements a full featured interface to the DNS.
// The package allows full control over what is send out to the DNS. 
//
// Resource Records are native types. They are not stored in wire format.
// Basic usage pattern for creating new Resource Record:
//
//         r := new(RR_TXT)
//         r.Hdr = RR_Header{Name: "a.miek.nl", Rrtype: TypeTXT, Class: ClassINET, Ttl: 3600}
//         r.TXT = "This is the content of the TXT record"
// 
package dns

// ErrShortWrite is defined in io, use that!

import (
	"os"
	"net"
	"strconv"
)

const (
	Year68         = 2 << (32 - 1) // For RFC1982 (Serial Arithmetic) calculations in 32 bits.
	DefaultMsgSize = 4096          // A standard default for larger than 512 packets.
	MaxMsgSize     = 65536         // Largest possible DNS packet.
	DefaultTtl     = 3600          // Default Ttl, used in New() for instance.
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

// A Conn is the lowest primative in this DNS library
// A hold both the UDP and TCP connection, but only one
// can be active at any one time.
type Conn struct {
	// The current UDP connection.
	UDP *net.UDPConn
	// The current TCP connection.
	TCP *net.TCPConn
	// The remote side of the connection.
	Addr net.Addr

	// Timeout in sec
	Timeout int

	// Number of attempts to try
	Attempts int
}

func (d *Conn) Read(p []byte) (n int, err os.Error) {
	if d.UDP != nil && d.TCP != nil {
		return 0, &Error{Error: "UDP and TCP or both non-nil"}
	}
	switch {
	case d.UDP != nil:
		n, err = d.UDP.Read(p)
		if err != nil {
			return n, err
		}
	case d.TCP != nil:
		n, err = d.TCP.Read(p[0:1])
		if err != nil || n != 2 {
			return n, err
		}
		l, _ := unpackUint16(p[0:1], 0)
		if l == 0 {
			return 0, &Error{Error: "received nil msg length", Server: d.Addr}
		}
		if int(l) > len(p) {
			return int(l), &Error{Error: "Buffer too small to read"}
		}
		n, err = d.TCP.Read(p)
		if err != nil {
			return n, err
		}
		i := n
		for i < int(l) {
			n, err = d.TCP.Read(p[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	return
}

func (d *Conn) Write(p []byte) (n int, err os.Error) {
	if d.UDP != nil && d.TCP != nil {
		return 0, &Error{Error: "UDP and TCP or both non-nil"}
	}

	var attempts int
	if d.Attempts == 0 {
		attempts = 1
	} else {
		attempts = d.Attempts
	}
	d.SetTimeout()

	switch {
	case d.UDP != nil:
		for a := 0; a < attempts; a++ {
			n, err = d.UDP.WriteTo(p, d.Addr)
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return 0, err
			}
		}
	case d.TCP != nil:
		for a := 0; a < attempts; a++ {
			l := make([]byte, 2)
			l[0], l[1] = packUint16(uint16(len(p)))
			n, err = d.TCP.Write(l)
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return n, err
			}
			if n != 2 {
				return n, &Error{Error: "Write failure"}
			}
			n, err = d.TCP.Write(p)
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return n, err
			}
		}
	}
	return
}

func (d *Conn) Close() (err os.Error) {
	if d.UDP != nil && d.TCP != nil {
		return &Error{Error: "UDP and TCP or both non-nil"}
	}
	switch {
	case d.UDP != nil:
		err = d.UDP.Close()
	case d.TCP != nil:
		err = d.TCP.Close()
	}
	return
}

func (d *Conn) SetTimeout() (err os.Error) {
	var sec int64
	if d.UDP != nil && d.TCP != nil {
		return &Error{Error: "UDP and TCP or both non-nil"}
	}
	sec = int64(d.Timeout)
	if sec == 0 {
		sec = 1
	}
	if d.UDP != nil {
		err = d.TCP.SetTimeout(sec * 1e9)
	}
	if d.TCP != nil {
		err = d.TCP.SetTimeout(sec * 1e9)
	}
	return
}

// Fix those here...!
// ReadTsig
// WriteTsig

func (d *Conn) Exchange(request []byte, nosend bool) (reply []byte, err os.Error) {
	var n int
	n, err = d.Write(request)
	if err != nil {
		return nil, err
	}
	// Layer violation to safe memory. (Its okay then.)
	if d.UDP == nil {
		reply = make([]byte, MaxMsgSize)
	} else {
		reply = make([]byte, DefaultMsgSize)
	}
	n, err = d.Read(reply)
	if err != nil {
		return nil, err
	}
	reply = reply[:n]
	return
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
