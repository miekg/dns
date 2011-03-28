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

// Query is used to communicate with the Query* functions.
type Query struct {
	// The query message. 
	Msg *Msg
	// A Conn. Its only required to fill out Conn.RemoteAddr.
	// The rest of the structure is filled in by the Query Functions.
	Conn *Conn
	// Any erros when querying are returned in Err. The caller
	// should just set this to nil.
	Err os.Error
}

// QueryUDP handles one query. It reads an incoming request from
// the in channel. The function f is executed in a seperate
// goroutine and performs the actual UDP query.
func QueryUDP(in, out chan Query, f func(*Conn, *Msg, chan Query)) {
	query("udp", in, out, f)
}
// Shoudl the chan be *Query??

// QueryTCP handles one query. It reads an incoming request from
// the in channel. The function f is executed in a seperate
// goroutine and performas the actual TCP query.
func QueryTCP(in, out chan Query, f func(*Conn, *Msg, chan Query)) {
	query("tcp", in, out, f)
}

// helper function.
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
			if f == nil {
				out <- Query{Err: ErrHandle}
			} else {
				go f(q.Conn, q.Msg, out)
			}
		}
	}
	panic("not reached")
}

// QueryAndServeTCP listens for incoming requests on channel in and
// then calls QueryTCP with f to the handle the request.
// It returns a channel on which the response is returned.
func QueryAndServeTCP(in chan Query, f func(*Conn, *Msg, chan Query)) chan Query {
	out := make(chan Query)
	go QueryTCP(in, out, f)
	return out
}

// QueryAndServeUDP listens for incoming requests on channel in and
// then calls QueryUDP with f to the handle the request.
// It returns a channel on which the response is returned.
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

// Send a query to the nameserver using res, but perform TSIG validation.
func (res *Resolver) Query(q *Query) (d *Msg, err os.Error) {
	var inb []byte
	in := new(Msg)
	port, err := check(res, q.Msg)
	if err != nil {
		return nil, err
	}

	sending, ok := q.Msg.Pack()
	if !ok {
		return nil, ErrPack
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

// Perform an incoming Ixfr or Axfr with Tsig validation. If the message 
// q's question section contains an AXFR type an Axfr is performed. If q's question
// section contains an IXFR type an Ixfr is performed.
func (res *Resolver) XfrTsig(q *Query, t *Tsig, m chan Xfr) {
	port, err := check(res, q.Msg)
	if err != nil {
		close(m)
		return
	}
	sending, ok := q.Msg.Pack()
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
		_, err = d.Write(sending)
		if err != nil {
			continue Server
		}
                // dont use d, use d.Conn -- more cleansup
		d.XfrRead(q.Msg, m) // check
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
