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

const ErrPack = "Failed to pack message"
const ErrServ = "No servers could be reached"
const ErrTsigKey = ""
const ErrTsigTime = ""
const ErrTsig = ""

type Resolver struct {
	Servers  []string            // servers to use
	Search   []string            // suffixes to append to local name
	Port     string              // what port to use
	Ndots    int                 // number of dots in name to trigger absolute lookup -- TODO
	Timeout  int                 // seconds before giving up on packet
	Attempts int                 // lost packets before giving up on server
	Tcp      bool                // use TCP
	Mangle   func([]byte) []byte // mangle the packet
	Rtt      map[string]int64    // Store round trip times
	Rrb      int                 // Last used server (for round robin)
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
//        in, err := res.Query(m, nil)                  // Ask the question
//
// Note that message id checking is left to the caller.
func (res *Resolver) Query(q *Msg, tsig *Tsig) (d *Msg, err os.Error) {
	var c net.Conn
	var inb []byte
	in := new(Msg)
	port, err := check(res, q)
	if err != nil {
		return nil, err
	}

	sending, ok := q.Pack()
	if !ok {
		return nil, &Error{Error: ErrPack}
	}

	for i := 0; i < len(res.Servers); i++ {
		d := new(Conn)
		server := res.Servers[i] + ":" + port
		t := time.Nanoseconds()
		if res.Tcp {
			c, err = net.Dial("tcp", "", server)
			d.TCP = c.(*net.TCPConn)
			d.Addr = d.TCP.RemoteAddr()
		} else {
			c, err = net.Dial("udp", "", server)
			d.UDP = c.(*net.UDPConn)
			d.Addr = d.UDP.RemoteAddr()
		}
		if err != nil {
			continue
		}
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

// Xfr is used in communicating with *xfr functions.
// This structure is returned on the channel.
type Xfr struct {
	Add bool // true is to be added, otherwise false
	RR
	Err os.Error
}

func (res *Resolver) Xfr(q *Msg, t *Tsig, m chan Xfr) {
	port, err := check(res, q)
	if err != nil {
		return
	}
	sending, ok := q.Pack()
	if !ok {
		return
	}

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
                        println(err.String())
                }
                d.XfrRead(q, m) // check
	}
	return
}

// Some assorted checks on the resolver
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
