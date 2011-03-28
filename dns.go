// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Extended and bugfixes by Miek Gieben

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
// The package dns supports querying, incoming/outgoing Axfr/Ixfr, TSIG, EDNS0,
// dynamic updates, notifies and DNSSEC validation/signing.
//
// Querying the DNS is done by using a Resolver structure. Basic use pattern for creating 
// a resolver:
//
//      res := new(Resolver)
//      res.Servers = []string{"127.0.0.1"} 
//      m := new(Msg)
//      m.MsgHdr.Recursion_desired = true
//      m.Question = make([]Question, 1)
//      m.Question[0] = Question{"miek.nl", TypeSOA, ClassINET}
//      in, err := res.Query(m)
//
// Server side programming is also supported.
// Basic use pattern for creating an UDP DNS server:
//
//      func handle(d *dns.Conn, i *dns.Msg) { /* handle request */ }
//
//      func listen(addr string, e chan os.Error) {
//            err := dns.ListenAndServeUDP(addr, handle)
//            e <- err
//      }
//      err := make(chan os.Error)
//      go listen("127.0.0.1:8053", err)
//
package dns

import (
        "io"
	"os"
	"net"
	"strconv"
)

const (
	Year68         = 2 << (32 - 1) // For RFC1982 (Serial Arithmetic) calculations in 32 bits.
	DefaultMsgSize = 4096          // A standard default for larger than 512 packets.
	MaxMsgSize     = 65536         // Largest possible DNS packet.
	DefaultTTL     = 3600          // Default Ttl.
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

// A Conn is the lowest primative in the dns package.
// A Conn holds both the UDP and TCP connection, but only one
// can be active any given time. 
type Conn struct {
	// The current UDP connection.
	UDP *net.UDPConn

	// The current TCP connection.
	TCP *net.TCPConn

	// The remote side of open the connection.
	Addr net.Addr

	// The remote port number of open the connection.
	Port int

	// If TSIG is used, this holds all the information.
        // If unused is must be nil.
	Tsig *Tsig

	// Timeout in sec before giving up on a connection.
	Timeout int

	// Number of attempts to try to Read/Write from/to a
	// connection.
	Attempts int

        // The remote addr which is going to be dialed.
        RemoteAddr string

        // Mangle the packet before writing it be feeding
        // it through this function.
        Mangle func([]byte) []byte

        // rtt times?
}

// Dial connects to the remote address raddr on the network net.
// If the string laddr is not empty, it is used as the local address
// for the connection. Any errors are return in err otherwise err is nil.
func Dial(n, laddr, raddr string) (*Conn, os.Error) {
        d := new(Conn)
        c, err := net.Dial(n, laddr, raddr)
        if err != nil {
                return nil, err
        }
        switch n {
        case "tcp":
                d.TCP = c.(*net.TCPConn)
                d.Addr = d.TCP.RemoteAddr()
                d.Port = d.TCP.RemoteAddr().(*net.TCPAddr).Port
        case "udp":
                d.UDP = c.(*net.UDPConn)
                d.Addr = d.UDP.RemoteAddr()
                d.Port = d.UDP.RemoteAddr().(*net.UDPAddr).Port
        }
        return d, nil
}

// Fill in a Conn from a TCPConn. If a is nil, the 
// remote address in the connection is used.
func (d *Conn) SetTCPConn(l *net.TCPConn, a net.Addr) {
        d.TCP = l
        d.UDP = nil
        if a == nil {
                d.Addr = l.RemoteAddr()
        }
        d.Port = d.Addr.(*net.TCPAddr).Port
}

// Fill in a Conn from a TCPConn. If a is nil, the 
// remote address in the connection is used.
func (d *Conn) SetUDPConn(l *net.UDPConn, a net.Addr) {
        d.TCP = nil
        d.UDP = l
        if a == nil {
                d.Addr = l.RemoteAddr()
        }
        d.Port = d.Addr.(*net.UDPAddr).Port
}

// Create a new buffer of the appropiate size. With
// TCP the buffer is 64K, with UDP the returned buffer
// has a length of 4K bytes.
func (d *Conn) NewBuffer() []byte {
	if d.TCP != nil {
		b := make([]byte, MaxMsgSize)
		return b
	}
	if d.UDP != nil {
		b := make([]byte, DefaultMsgSize)
		return b
	}
	return nil
}

// ReadMsg reads a dns message m from d.
// Any errors of the underlaying Read call are returned.
func (d *Conn) ReadMsg(m *Msg) os.Error {
	in := d.NewBuffer()
	n, err := d.Read(in)
	if err != nil {
		return err
	}
	in = in[:n]
	ok := m.Unpack(in)
	if !ok {
                return ErrUnpack
	}
	return nil
}

// WriteMsg writes dns message m to d.
// Any errors of the underlaying Write call are returned.
func (d *Conn) WriteMsg(m *Msg) os.Error {
	out, ok := m.Pack()
	if !ok {
		return ErrPack
	}
	_, err := d.Write(out)
	if err != nil {
		return err
	}
	return nil
}

// Read implements the standard Read interface:
// it reads from d. If there was an error
// reading that error is returned; otherwise err is nil.
func (d *Conn) Read(p []byte) (n int, err os.Error) {
	if d.UDP != nil && d.TCP != nil {
		return 0, ErrConn
	}
	switch {
	case d.UDP != nil:
		var addr net.Addr
		n, addr, err = d.UDP.ReadFromUDP(p)
		if err != nil {
			return n, err
		}
		d.Addr = addr
		d.Port = addr.(*net.UDPAddr).Port
	case d.TCP != nil:
		if len(p) < 1 {
			return 0, io.ErrShortBuffer
		}
		n, err = d.TCP.Read(p[0:2])
		if err != nil || n != 2 {
			return n, err
		}
		d.Addr = d.TCP.RemoteAddr()
		d.Port = d.TCP.RemoteAddr().(*net.TCPAddr).Port
		l, _ := unpackUint16(p[0:2], 0)
		if l == 0 {
			return 0, ErrShortRead
		}
		if int(l) > len(p) {
			return int(l), io.ErrShortBuffer
		}
		n, err = d.TCP.Read(p[:l])
		if err != nil {
			return n, err
		}
		i := n
		for i < int(l) {
			j, err := d.TCP.Read(p[i:int(l)])
			if err != nil {
				return i, err
			}
			i += j
		}
		n = i
	}
	if d.Tsig != nil {
		// Check the TSIG that we should be read
		_, err = d.Tsig.Verify(p)
		if err != nil {
			return
		}
	}
	return
}

// Write implements the standard Write interface:
// It write data to d. If there was an error writing
// that error is returned; otherwise err is nil
func (d *Conn) Write(p []byte) (n int, err os.Error) {
	if d.UDP != nil && d.TCP != nil {
		return 0, ErrConn
	}

	var attempts int
	var q []byte
	if d.Attempts == 0 {
		attempts = 1
	} else {
		attempts = d.Attempts
	}
        // Mangle before TSIG?
        if d.Mangle != nil {
                p = d.Mangle(p)
        }

	d.SetTimeout()
	if d.Tsig != nil {
		// Create a new buffer with the TSIG added.
		q, err = d.Tsig.Generate(p)
		if err != nil {
			return 0, err
		}
	} else {
		q = p
	}

	switch {
	case d.UDP != nil:
		for a := 0; a < attempts; a++ {
			n, err = d.UDP.WriteTo(q, d.Addr)
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
			l[0], l[1] = packUint16(uint16(len(q)))
			n, err = d.TCP.Write(l)
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return n, err
			}
			if n != 2 {
				return n, io.ErrShortWrite
			}
			n, err = d.TCP.Write(q)
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return n, err
			}
			i := n
			if i < len(q) {
				j, err := d.TCP.Write(q[i:len(q)])
				if err != nil {
					if e, ok := err.(net.Error); ok && e.Timeout() {
						// We are half way in our write...
						continue
					}
					return i, err
				}
				i += j
			}
			n = i
		}
	}
	return
}

// Close closes the connection in d. Possible
// errors are returned in err; otherwise it is nil.
func (d *Conn) Close() (err os.Error) {
	if d.UDP != nil && d.TCP != nil {
		return ErrConn
	}
	switch {
	case d.UDP != nil:
		err = d.UDP.Close()
	case d.TCP != nil:
		err = d.TCP.Close()
	}
	return
}

// SetTimeout sets the timeout of the socket
// that is contained in d.
func (d *Conn) SetTimeout() (err os.Error) {
	var sec int64
	if d.UDP != nil && d.TCP != nil {
		return ErrConn
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

// Exchange combines a Write and a Read.
// First the request is written to d and then it waits
// for a reply with Read. 
// If nosend is true, the write is skipped.
func (d *Conn) Exchange(request []byte, nosend bool) (reply []byte, err os.Error) {
	var n int
	if !nosend {
		n, err = d.Write(request)
		if err != nil {
			return nil, err
		}
	}
	reply = d.NewBuffer()
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
