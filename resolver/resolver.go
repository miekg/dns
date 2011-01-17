// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS resolver client: see RFC 1035.
// A dns resolver is to be run as a seperate goroutine. 
// For every reply the resolver answers by sending the
// received packet (with a possible error) back on the channel.
// 
// Basic usage pattern for setting up a resolver:
//
//        res := new(Resolver)
//        ch := res.NewQuerier()              // start new resolver
//        res.Servers = []string{"127.0.0.1"} // set the nameserver
//
//        m := new(Msg)                       // prepare a new message
//        m.MsgHdr.Recursion_desired = true   // header bits
//        m.Question = make([]Question, 1)    // 1 RR in question sec.
//        m.Question[0] = Question{"miek.nl", TypeSOA, ClassINET}
//        ch <- Msg{m, nil}                   // send the query
//        in := <-ch                          // wait for reply
//
// Note that message id checking is left to the caller
//
package resolver

import (
	"os"
	"net"
	"dns"
)

const packErr = "Failed to pack message"
const servErr = "No servers could be reached"

// When communicating with a resolver, we use this structure
// to send packets to it, for sending Error must be nil.
// A resolver responds with a reply packet and a possible error.
// Sending a nil message instructs to resolver to stop.
type Msg struct {
	Dns   *dns.Msg
	Error os.Error
}

type Resolver struct {
	Servers  []string            // servers to use
	Search   []string            // suffixes to append to local name
	Port     string              // what port to use
	Ndots    int                 // number of dots in name to trigger absolute lookup
	Timeout  int                 // seconds before giving up on packet
	Attempts int                 // lost packets before giving up on server
	Rotate   bool                // round robin among servers
	Tcp      bool                // use TCP
	Mangle   func([]byte) []byte // mangle the packet
}

// Start a new resolver as a goroutine, return the communication channel.
// Note the a limit amount of sanity checking is done. There is for instance
// no query id matching.
func (res *Resolver) NewQuerier() (ch chan Msg) {
	ch = make(chan Msg)
	go query(res, ch)
	return
}

// The query function.
func query(res *Resolver, msg chan Msg) {
	// error checking, robustness
	var (
		c    net.Conn
		err  os.Error
		in   *dns.Msg
		port string
	)
	// len(res.Server) == 0 can be perfectly valid, when setting up the resolver
	if res.Port == "" {
		port = "53"
	} else {
		port = res.Port
	}

	for {
		select {
		case out := <-msg: //msg received
			if out.Dns == nil {
				// nil message, quit the goroutine
				msg <- Msg{nil, nil}
				close(msg)
				return
			}

			var cerr os.Error
			//if len(name) >= 256 {
			if out.Dns.Id == 0 {
				// No Id sed, set it
				out.Dns.SetId()
			}
			sending, ok := out.Dns.Pack()
			if !ok {
				msg <- Msg{nil, &dns.Error{Error: packErr}}
				continue
			}

			for i := 0; i < len(res.Servers); i++ {
				server := res.Servers[i] + ":" + port
				if res.Tcp {
					c, cerr = net.Dial("tcp", "", server)
				} else {
					c, cerr = net.Dial("udp", "", server)
				}
				if cerr != nil {
					err = cerr
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
			}
			if err != nil {
				msg <- Msg{nil, err}
			} else {
				msg <- Msg{in, nil}
			}
		}
	}
	return
}

// Start a new xfr as a goroutine, return a channel of Msg.
// Channel will be closed when the axfr is finished, until
// that time new messages will appear on the channel
func (res *Resolver) NewXfer() (ch chan Msg) {
	ch = make(chan Msg)
	go axfr(res, ch)
	return
}

func axfr(res *Resolver, msg chan Msg) {
	var port string
	var err os.Error
	var in *dns.Msg
	if res.Port == "" {
		port = "53"
	} else {
		port = res.Port
	}

	for {
		select {
		case out := <-msg: // msg received
			if out.Dns == nil {
				// stop
				msg <- Msg{nil, nil}
				close(msg)
				return
			}

			out.Dns.SetId()
			sending, ok := out.Dns.Pack()
			if !ok {
				msg <- Msg{nil, &dns.Error{Error: packErr}}
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
						in, cerr = exchangeTCP(c, sending, res, false)
					}

					if cerr != nil {
						// Failed to send, try the next
						err = cerr
						c.Close()
						continue SERVER
					}
					// if in.Dns.Id != out.Id // error
					if first {
						if !checkSOA(in, true) {
							// SOA record not there...
							c.Close()
							continue SERVER
						}
						first = !first
					}

					if !first {
						if !checkSOA(in, false) {
							// Soa record not the last one
							msg <- Msg{in, nil}
							continue
							// next
						} else {
							c.Close()
							msg <- Msg{in, nil}
							close(msg)
							return
						}
					}
				}
				println("Should never be reached")
				return
			}
			msg <- Msg{nil, err}
			close(msg)
			return
		}
	}
	return
}

// Send a request on the connection and hope for a reply.
// Up to res.Attempts attempts.
func exchangeUDP(c net.Conn, m []byte, r *Resolver, send bool) (*dns.Msg, os.Error) {
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

		in := new(dns.Msg)
		if !in.Unpack(buf) {
			continue
		}
		return in, nil
	}
	return nil, &dns.Error{Error: servErr}
}

// Up to res.Attempts attempts.
func exchangeTCP(c net.Conn, m []byte, r *Resolver, send bool) (*dns.Msg, os.Error) {
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
			err := sendTCP(m,c)
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
		in := new(dns.Msg)
		if !in.Unpack(buf) {
			continue
		}
		return in, nil
	}
	return nil, &dns.Error{Error: servErr}
}

func sendUDP(m []byte,c net.Conn) os.Error {
        _, err := c.Write(m)
        if err != nil {
                return err
        }
        return nil
}

func recvUDP(c net.Conn) ([]byte, os.Error) {
        m := make([]byte, dns.DefaultMsgSize) // More than enough???
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
                return nil,err
        }
        length := uint16(l[0])<<8 | uint16(l[1])
        if length == 0 {
                return nil, &dns.Error{Error: "received nil msg length", Server: c.RemoteAddr().String()}
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
func checkSOA(in *dns.Msg, first bool) bool {
	if len(in.Answer) > 0 {
		if first {
			return in.Answer[0].Header().Rrtype == dns.TypeSOA
		} else {
			return in.Answer[len(in.Answer)-1].Header().Rrtype == dns.TypeSOA
		}
	}
	return false
}
