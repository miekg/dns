// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS resolver client: see RFC 1035.

package dns

import (
	"os"
	"net"
	"time"
)

type Resolver struct {
	Servers  []string            // servers to use
	Search   []string            // suffixes to append to local name (not implemented)
	Port     string              // what port to use
	Ndots    int                 // number of dots in name to trigger absolute lookup (not implemented)
	Timeout  int                 // seconds before giving up on packet
	Attempts int                 // lost packets before giving up on server
	Tcp      bool                // use TCP
	Mangle   func([]byte) []byte // mangle the packet
	Rtt      map[string]int64    // Store round trip times
	Rrb      int                 // Last used server (for round robin)
}

// Send a query to the nameserver using the res.
func (res *Resolver) Query(q *Msg) (d *Msg, err os.Error) {
	return res.QueryTsig(q, nil)
}

// Send a query to the nameserver using res, but perform TSIG validation.
func (res *Resolver) QueryTsig(q *Msg, tsig *Tsig) (d *Msg, err os.Error) {
	var c net.Conn
	var inb []byte
	in := new(Msg)
	port, err := check(res, q)
	if err != nil {
		return nil, err
	}

	sending, ok := q.Pack()
	if !ok {
		return nil, ErrPack
	}
	if res.Mangle != nil {
		sending = res.Mangle(sending)
	}

	for i := 0; i < len(res.Servers); i++ {
		d := new(Conn)
		server := res.Servers[i] + ":" + port
		t := time.Nanoseconds()
		if res.Tcp {
			c, err = net.Dial("tcp", "", server)
			if err != nil {
				continue
			}
			d.TCP = c.(*net.TCPConn)
			d.Addr = d.TCP.RemoteAddr()
		} else {
			c, err = net.Dial("udp", "", server)
			if err != nil {
				continue
			}
			d.UDP = c.(*net.UDPConn)
			d.Addr = d.UDP.RemoteAddr()
		}

		d.Tsig = tsig
		inb, err = d.Exchange(sending, false)
		if err != nil {
			continue
		}
		in.Unpack(inb) // Discard error.
		res.Rtt[server] = time.Nanoseconds() - t
		c.Close()
		break
	}
	if err != nil {
		return nil, err
	}
	return in, nil
}

// Perform an incoming Ixfr or Axfr. If the message q's question
// section contains an AXFR type an Axfr is performed. If q's question
// section contains an IXFR type an Ixfr is performed.
func (res *Resolver) Xfr(q *Msg, m chan Xfr) {
	res.XfrTsig(q, nil, m)
}

// Perform an incoming Ixfr or Axfr with Tsig validation. If the message 
// q's question section contains an AXFR type an Axfr is performed. If q's question
// section contains an IXFR type an Ixfr is performed.
func (res *Resolver) XfrTsig(q *Msg, t *Tsig, m chan Xfr) {
	port, err := check(res, q)
	if err != nil {
		close(m)
		return
	}
	sending, ok := q.Pack()
	if !ok {
		close(m)
		return
	}
	// No defer close(m) as m is closed in d.XfrRead()
Server:
	for i := 0; i < len(res.Servers); i++ {
		server := res.Servers[i] + ":" + port
		c, err := net.Dial("tcp", "", server)
		if err != nil {
			continue Server
		}
		d := new(Conn)
		d.TCP = c.(*net.TCPConn)
		d.Addr = d.TCP.RemoteAddr()
		d.Tsig = t

		_, err = d.Write(sending)
		if err != nil {
			continue Server
		}
		d.XfrRead(q, m) // check
	}
	return
}

func check(res *Resolver, q *Msg) (port string, err os.Error) {
	if res.Port == "" {
		port = "53"
	} else {
		port = res.Port
	}
	if res.Rtt == nil {
		res.Rtt = make(map[string]int64)
	}
	if q.Id == 0 {
		q.Id = Id()
	}
	return
}
