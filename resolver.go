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

// Start an AXFR, q should contain a message with the question
// for an AXFR ("miek.nl" ANY AXFR. All incoming axfr snippets
// are returned on the channel m. The function closes the 
// channel to signal the end of the AXFR.
func (res *Resolver) Axfr(q *Msg, m chan *Msg) {
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

	sending, ok := q.Pack()
	if !ok {
		m <- nil
		return
	}

SERVER:
	for i := 0; i < len(res.Servers); i++ {
		server := res.Servers[i] + ":" + port
		c, cerr := net.Dial("tcp", "", server)
		if cerr != nil {
			err = cerr
			continue SERVER
		}
		first := true
		// Start the AXFR
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
				continue SERVER
			}
			if in.Id != q.Id {
				m <- nil
				return
			}

			if first {
				if !checkSOA(in, true) {
					c.Close()
					continue SERVER
				}
				m <- in
				first = !first
			}

			if !first {
				if !checkSOA(in, false) {
					// Soa record not the last one
					m <- in
					continue
				} else {
					c.Close()
					m <- in
					close(m)
					return
				}
			}
		}
		panic("not reached")
		return
	}
	close(m)
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
	if i < int(length) {
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
func checkSOA(in *Msg, first bool) bool {
	if len(in.Answer) > 0 {
		if first {
			return in.Answer[0].Header().Rrtype == TypeSOA
		} else {
			return in.Answer[len(in.Answer)-1].Header().Rrtype == TypeSOA
		}
	}
	return false
}
