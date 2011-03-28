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

type Query struct {
	Msg  *Msg
	Conn *Conn
	Err  os.Error
}

// A query implementation that is asyn. and concurrent. Is also
// completely mirrors the server side implementation

func QueryTCP(in, out chan Query, f func(*Conn, *Msg, chan Query)) {
	query("tcp", in, out, f)
}

func QueryUDP(in, out chan Query, f func(*Conn, *Msg, chan Query)) {
	query("udp", in, out, f)
}

func query(n string, in, out chan Query, f func(*Conn, *Msg, chan Query)) {
	for {
		select {
		case q := <-in:
			c, err := net.Dial(n, "", q.Conn.RemoteAddr)
			if err != nil {
				//out <- nil
			}
                        if n == "tcp" {
                                q.Conn.SetTCPConn(c.(*net.TCPConn), nil)
                        } else {
                                q.Conn.SetUDPConn(c.(*net.UDPConn), nil)
                        }
			go f(q.Conn, q.Msg, out)
		}
	}
	panic("not reached")
}

func QueryAndServeTCP(in chan Query, f func(*Conn, *Msg, chan Query)) chan Query {
	out := make(chan Query)
	go QueryTCP(in, out, f)
	return out
}

func QueryAndServeUDP(in chan Query, f func(*Conn, *Msg, chan Query)) chan Query {
	out := make(chan Query)
	go QueryUDP(in, out, f)
	return out
}

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
		var d *Conn
		server := res.Servers[i] + ":" + port
		t := time.Nanoseconds()
		if res.Tcp {
			d, err = Dial("tcp", "", server)
			if err != nil {
				continue
			}
		} else {
			d, err = Dial("udp", "", server)
			if err != nil {
				continue
			}
		}
		d.Tsig = tsig
		inb, err = d.Exchange(sending, false)
		if err != nil {
			continue
		}
		in.Unpack(inb) // Discard error.
		res.Rtt[server] = time.Nanoseconds() - t
		d.Close()
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
		d, err := Dial("tcp", "", server)
		if err != nil {
			continue Server
		}
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
