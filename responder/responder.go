// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS server

// For every reply the resolver answers by sending the
// received packet (with a possible error) back on the channel.
package responder

import (
	"os"
	"net"
	"dns"
	"fmt"
)
// Some helper function for sending tcp/udp queries, like those
// in resolver.go, but then exported?

type Server struct {
	Address string              // interface to use, for multiple interfaces, use multiple servers
	Port      string              // what port to use
	Timeout   int                 // seconds before giving up on packet
	Tcp       bool                // use TCP
	Mangle    func([]byte) []byte // mangle the packet, before sending
}

// Every nameserver must implement the Handler interface.
type Responder interface {
	// Receives the raw message content
	ResponderUDP(c *net.UDPConn, raddr net.Addr, in []byte)
	// Receives the raw message content
	ResponderTCP(c *net.TCPConn, raddr net.Addr, in []byte)
}

// This is a NAMESERVER
// Stop it by sending it true over the channel
// NewResponder returns a channel, for communication (start/stop)
// caN we use the channel for other stuff??
func (res *Server) NewResponder(h Responder, ch chan bool) os.Error {
	var port string
	if len(res.Address) == 0 {
		// We cannot start responding without an addresss
		return nil
	}
	if res.Port == "" {
		port = "53"
	} else {
		port = res.Port
	}
	switch res.Tcp {
	case true:
                /* Todo tcp conn. */
	case false:
		udpaddr, _ := net.ResolveUDPAddr(res.Address + ":" + port)
		c, _ := net.ListenUDP("udp", udpaddr)
	foreverudp:
		for {
			select {
			case <-ch:
				c.Close()
				break foreverudp
			default:
				m := make([]byte, 4096) // Can we take this out of this loop TODO(mg)
				n, raddr, err := c.ReadFrom(m)
				if err != nil {
					//continue
				}
				m = m[:n]
				go h.ResponderUDP(c, raddr, m)
			}
		}
	}
	return nil
}

// The raw packet
func handlerUDP(c *net.UDPConn, raddr net.Addr, i []byte) {
	in := new(dns.Msg)
	in.Unpack(i)
	fmt.Printf("%v\n", in)

	m := new(dns.Msg)
	m.MsgHdr.Id = in.MsgHdr.Id // Copy the Id over
	m.MsgHdr.Authoritative = true
	m.MsgHdr.Response = true
	m.MsgHdr.Rcode = dns.RcodeSuccess
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{"miek.nl.", dns.TypeTXT, dns.ClassINET}
	m.Answer = make([]dns.RR, 1)
	a := new(dns.RR_TXT)
	a.Hdr = dns.RR_Header{Name: "miek.nl.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600}
	a.Txt = "dit dan"
	m.Answer[0] = a
	out, _ := m.Pack()
	c.WriteTo(out, raddr)
}
