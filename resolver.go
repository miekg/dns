// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS resolver client: see RFC 1035.

package dns

import (
	"os"
	"net"
)

// Query is used to communicate with the Query* functions.
type Query struct {
	// The query message. 
	Msg *Msg
	// A Conn. Its only required to fill out Conn.RemoteAddr.
        // Optionally you may set Conn.Tsig if TSIG is required.
	// The rest of the structure is filled by the Query functions.
	Conn *Conn
	// Any error when querying is returned in Err. The caller
	// should just set this to nil.
	Err os.Error
        // Query time in here?
}

// QueryUDP handles one query. It reads an incoming request from
// the in channel. The function f is executed in a seperate
// goroutine and performs the actual UDP query.
func QueryUDP(in, out chan Query, f func(*Conn, *Msg, chan Query)) {
	query("udp", in, out, f)
}

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
				out <- Query{Err: err}
			}
			if n == "tcp" {
				q.Conn.SetTCPConn(c.(*net.TCPConn), nil)
			} else {
				q.Conn.SetUDPConn(c.(*net.UDPConn), nil)
			}
			if f == nil {
				go QueryDefault(q.Conn, q.Msg, out)
			} else {
				go f(q.Conn, q.Msg, out)
			}
		}
	}
	panic("not reached")
}

// Default Handler when none is given.
func QueryDefault(d *Conn, m *Msg, q chan Query) {
        buf, ok := m.Pack()
        if !ok {
                q <- Query{nil, d, ErrPack}
        }
        ret, err := d.Exchange(buf, false)
        if err != nil {
                q <- Query{nil, d, err}
        }
        out := new(Msg)
        if ok1 := out.Unpack(ret); !ok1 {
                q <- Query{nil, d, ErrUnpack}
        }
        q <- Query{out, d, nil}
        return
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

/*      // alg for querying a list of servers, not sure if we going to keep it
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
*/
