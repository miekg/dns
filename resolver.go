// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS resolver client: see RFC 1035.

package dns
// TODO: refacter this

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
		in.Unpack(inb)
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

// Start an IXFR, q should contain a *Msg with the question
// for an IXFR: "miek.nl" ANY IXFR. RRs that should be added
// have Xfr.Add set to true otherwise it is false.
// Channel m is closed when the IXFR ends.
func (res *Resolver) Ixfr(q *Msg, m chan Xfr) {
	var (
		x   Xfr
		inb []byte
	)
	in := new(Msg)
	port, err := check(res, q)
	if err != nil {
		return
	}

	defer close(m)
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
		var serial uint32 // The first serial seen is the current server serial
                d := new(Conn)
                d.TCP = c.(*net.TCPConn)
                d.Addr = d.TCP.RemoteAddr()

		first := true
		defer c.Close()
		for {
			if first {
				inb, err = d.Exchange(sending, false)
			} else {
				inb, err = d.Exchange(sending, true)
			}
			if err != nil {
				c.Close()
				continue Server
			}

			in.Unpack(inb)  // error!
			if in.Id != q.Id {
				return
			}

			if first {
				// A single SOA RR signals "no changes"
				if len(in.Answer) == 1 && checkXfrSOA(in, true) {
					return
				}

				// But still check if the returned answer is ok
				if !checkXfrSOA(in, true) {
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
func (res *Resolver) AxfrTSIG(q *Msg, m chan Xfr, t *Tsig) {
	var inb []byte
	in := new(Msg)
	port, err := check(res, q)
	if err != nil {
		return
	}

	defer close(m)
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

		first := true
		defer c.Close() // TODO(mg): if not open?
		for {
			if first {
				inb, err = d.Exchange(sending, false)
			} else {
				inb, err = d.Exchange(sending, true)
			}
			if err != nil {
				c.Close()
				continue Server
			}

                        in.Unpack(inb)
			if in.Id != q.Id {
				c.Close()
				return
			}

			if first {
				if !checkXfrSOA(in, true) {
					c.Close()
					continue Server
				}
				first = !first
			}

			if !first {
				if !checkXfrSOA(in, false) {
					// Soa record not the last one
					sendMsg(in, m, false)
					continue
				} else {
					sendMsg(in, m, true)
					return
				}
			}
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
	var inb []byte
	port, err := check(res, q)
	if err != nil {
		return
	}
	in := new(Msg)

	defer close(m)
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

		first := true
		defer c.Close() // TODO(mg): if not open?
		for {
			if first {
				inb, err = d.Exchange(sending, false)
			} else {
				inb, err = d.Exchange(sending, true)
			}
			if err != nil {
				c.Close()
				continue Server
			}
                        if !in.Unpack(inb) {
                                println("Failed to unpack")
                        }
			if in.Id != q.Id {
				c.Close()
				return
			}
			if first {
				if !checkXfrSOA(in, true) {
					c.Close()
					continue Server
				}
				first = !first
			}

			if !first {
				if !checkXfrSOA(in, false) {
					// Soa record not the last one
					sendMsg(in, m, false)
					continue
				} else {
					sendMsg(in, m, true)
					return
				}
			}
		}
		panic("not reached")
		return
	}
	return
}

// Check if he SOA record exists in the Answer section of 
// the packet. If first is true the first RR must be a soa
// if false, the last one should be a SOA
func checkXfrSOA(in *Msg, first bool) bool {
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
func sendMsg(in *Msg, c chan Xfr, nosoa bool) {
	x := Xfr{Add: true}
	for k, r := range in.Answer {
		if nosoa && k == len(in.Answer)-1 {
			continue
		}
		x.RR = r
		c <- x
	}
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
