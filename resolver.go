// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS resolver client: see RFC 1035.

package dns

import (
	"os"
	"net"
)

const packErr = "Failed to pack message"
const servErr = "No servers could be reached"

type Resolver struct {
	Servers  []string            // servers to use
	Search   []string            // suffixes to append to local name
	Port     string              // what port to use
	Ndots    int                 // number of dots in name to trigger absolute lookup -- TODO
	Timeout  int                 // seconds before giving up on packet
	Attempts int                 // lost packets before giving up on server
	Rotate   bool                // round robin among servers -- TODO
	Tcp      bool                // use TCP
	Mangle   func([]byte) []byte // mangle the packet
	// rtt map[string]int server->int, smaller is faster 0, -1 is unreacheble
}

// Basic usage pattern for setting up a resolver:
//
//        res := new(Resolver)
//        res.Servers = []string{"127.0.0.1"}           // set the nameserver
//
//        m := new(Msg)                                 // prepare a new message
//        m.MsgHdr.Recursion_desired = true             // header bits
//        m.Question = make([]Question, 1)              // 1 RR in question section
//        m.Question[0] = Question{"miek.nl", TypeSOA, ClassINET}
//        in, err := res.Query(m)                       // Ask the question
//
// Note that message id checking is left to the caller.
func (res *Resolver) Query(q *Msg) (d *Msg, err os.Error) {
	var (
		c    net.Conn
		in   *Msg
		port string
	)
	if len(res.Servers) == 0 {
		return nil, &Error{Error: "No servers defined"}
	}
	// len(res.Server) == 0 can be perfectly valid, when setting up the resolver
	// It is now
	if res.Port == "" {
		port = "53"
	} else {
		port = res.Port
	}

	if q.Id == 0 {
		// No Id sed, set it
		q.SetId()
	}
	sending, ok := q.Pack()
	if !ok {
		return nil, &Error{Error: packErr}
	}

	for i := 0; i < len(res.Servers); i++ {
		server := res.Servers[i] + ":" + port
		if res.Tcp {
			c, err = net.Dial("tcp", "", server)
		} else {
			c, err = net.Dial("udp", "", server)
		}
		if err != nil {
			continue
		}
		if res.Tcp {
			in, err = exchangeTCP(c, sending, res, true)
		} else {
			in, err = exchangeUDP(c, sending, res, true)
		}

		// Check id in.id != out.id, should be checked in the client!
		c.Close()
		if err != nil {
			continue
		}
		break
	}
	if err != nil {
		return nil, err
	}
	return in, nil
}

// Xfr is used in communicating with *xfr functions.
// This structure is returned on the channel.
type Xfr struct {
	Add bool // true is to be added, otherwise false
	RR
}

// Start an IXFR, q should contain a *Msg with the question
// for an IXFR: "miek.nl" ANY IXFR. RRs that should be added
// have Xfr.Add set to true otherwise it is false.
// Channel m is closed when the IXFR ends.
func (res *Resolver) Ixfr(q *Msg, m chan Xfr) {
	var port string
	var err os.Error
	var in *Msg
	var x Xfr
	if res.Port == "" {
		port = "53"
	} else {
		port = res.Port
	}

	var _ = err // TODO(mg)

	if q.Id == 0 {
		q.SetId()
	}

	defer close(m)
	sending, ok := q.Pack()
	if !ok {
		return
	}

Server:
	for i := 0; i < len(res.Servers); i++ {
		server := res.Servers[i] + ":" + port
		c, cerr := net.Dial("tcp", "", server)
		if cerr != nil {
			err = cerr
			continue Server
		}
		first := true
		var serial uint32 // The first serial seen is the current server serial
		var _ = serial

		defer c.Close()
		for {
			if first {
				in, cerr = exchangeTCP(c, sending, res, true)
			} else {
				in, err = exchangeTCP(c, sending, res, false)
			}

			if cerr != nil {
				// Failed to send, try the next
				err = cerr
				c.Close()
				continue Server
			}
			if in.Id != q.Id {
				return
			}

			if first {
				// A single SOA RR signals "no changes"
				if len(in.Answer) == 1 && checkAxfrSOA(in, true) {
					return
				}

				// But still check if the returned answer is ok
				if !checkAxfrSOA(in, true) {
					c.Close()
					continue Server
				}
				// This serial is important
				serial = in.Answer[0].(*RR_SOA).Serial
				first = !first
			}

			// Now we need to check each message for SOA records, to see what we need to do
			x.Add = true
			if !first {
				for k, r := range in.Answer {
					// If the last record in the IXFR contains the servers' SOA,  we should quit
					if r.Header().Rrtype == TypeSOA {
						switch {
						case r.(*RR_SOA).Serial == serial:
							if k == len(in.Answer)-1 {
								// last rr is SOA with correct serial
								//m <- r dont' send it
								return
							}
							x.Add = true
							if k != 0 {
								// Intermediate SOA
								continue
							}
						case r.(*RR_SOA).Serial != serial:
							x.Add = false
							continue // Don't need to see this SOA
						}
					}
					x.RR = r
					m <- x
				}
			}
			return
		}
		panic("not reached")
		return
	}
	return
}

// Start an AXFR, q should contain a message with the question
// for an AXFR: "miek.nl" ANY AXFR. The closing SOA isn't
// returned over the channel, so the caller will receive 
// the zone as-is. Xfr.Add is always true.
// The channel is closed to signal the end of the AXFR.
func (res *Resolver) Axfr(q *Msg, m chan Xfr) {
	var port string
	var err os.Error
	var in *Msg
	if res.Port == "" {
		port = "53"
	} else {
		port = res.Port
	}

	var _ = err // TODO(mg)

	if q.Id == 0 {
		q.SetId()
	}

	defer close(m)
	sending, ok := q.Pack()
	if !ok {
		return
	}
Server:
	for i := 0; i < len(res.Servers); i++ {
		server := res.Servers[i] + ":" + port
		c, cerr := net.Dial("tcp", "", server)
		if cerr != nil {
			err = cerr
			continue Server
		}
		first := true
		defer c.Close() // TODO(mg): if not open?
		for {
			if first {
				in, cerr = exchangeTCP(c, sending, res, true)
			} else {
				in, err = exchangeTCP(c, sending, res, false)
			}

			if cerr != nil {
				// Failed to send, try the next
				err = cerr
				c.Close()
				println("AGIAIN")
				continue Server
			}
			if in.Id != q.Id {
				c.Close()
				return
			}

			if first {
				if !checkAxfrSOA(in, true) {
					c.Close()
					continue Server
				}
				first = !first
			}

			if !first {
				if !checkAxfrSOA(in, false) {
					// Soa record not the last one
					sendFromMsg(in, m, false)
					continue
				} else {
					sendFromMsg(in, m, true)
					return
				}
			}
		}
		panic("not reached")
		return
	}
	return
}

// Send a request on the connection and hope for a reply.
// Up to res.Attempts attempts. If send is false, nothing
// is send.
func exchangeUDP(c net.Conn, m []byte, r *Resolver, send bool) (*Msg, os.Error) {
	var timeout int64
	var attempts int
	if r.Mangle != nil {
		m = r.Mangle(m)
	}
	if r.Timeout == 0 {
		timeout = 1
	} else {
		timeout = int64(r.Timeout)
	}
	if r.Attempts == 0 {
		attempts = 1
	} else {
		attempts = r.Attempts
	}
	for a := 0; a < attempts; a++ {
		if send {
			err := sendUDP(m, c)
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return nil, err
			}
		}

		c.SetReadTimeout(timeout * 1e9) // nanoseconds
		buf, err := recvUDP(c)
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Timeout() {
				continue
			}
			return nil, err
		}

		in := new(Msg)
		if !in.Unpack(buf) {
			continue
		}
		return in, nil
	}
	return nil, &Error{Error: servErr}
}

// Up to res.Attempts attempts.
func exchangeTCP(c net.Conn, m []byte, r *Resolver, send bool) (*Msg, os.Error) {
	var timeout int64
	var attempts int
	if r.Mangle != nil {
		m = r.Mangle(m)
	}
	if r.Timeout == 0 {
		timeout = 1
	} else {
		timeout = int64(r.Timeout)
	}
	if r.Attempts == 0 {
		attempts = 1
	} else {
		attempts = r.Attempts
	}

	for a := 0; a < attempts; a++ {
		// only send something when told so
		if send {
			err := sendTCP(m, c)
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return nil, err
			}
		}

		c.SetReadTimeout(timeout * 1e9) // nanoseconds
		// The server replies with two bytes length
		buf, err := recvTCP(c)
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Timeout() {
				continue
			}
			return nil, err
		}
		in := new(Msg)
		if !in.Unpack(buf) {
			continue
		}
		return in, nil
	}
	return nil, &Error{Error: servErr}
}

func sendUDP(m []byte, c net.Conn) os.Error {
	_, err := c.Write(m)
	if err != nil {
		return err
	}
	return nil
}

func recvUDP(c net.Conn) ([]byte, os.Error) {
	m := make([]byte, DefaultMsgSize) // More than enough???
	n, err := c.Read(m)
	if err != nil {
		return nil, err
	}
	m = m[:n]
	return m, nil
}

func sendTCP(m []byte, c net.Conn) os.Error {
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

func recvTCP(c net.Conn) ([]byte, os.Error) {
	l := make([]byte, 2) // receiver length
	// The server replies with two bytes length
	_, err := c.Read(l)
	if err != nil {
		return nil, err
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
	for i < int(length) {
		n, err = c.Read(m[i:])
		if err != nil {
			return nil, err
		}
		i += n
	}
	return m, nil
}

// Check if he SOA record exists in the Answer section of 
// the packet. If first is true the first RR must be a soa
// if false, the last one should be a SOA
func checkAxfrSOA(in *Msg, first bool) bool {
	if len(in.Answer) > 0 {
		if first {
			return in.Answer[0].Header().Rrtype == TypeSOA
		} else {
			return in.Answer[len(in.Answer)-1].Header().Rrtype == TypeSOA
		}
	}
	return false
}

// Send the answer section to the channel
func sendFromMsg(in *Msg, c chan Xfr, nosoa bool) {
	x := Xfr{Add: true}
	for k, r := range in.Answer {
		if nosoa && k == len(in.Answer)-1 {
			continue
		}
		x.RR = r
		c <- x
	}
}
