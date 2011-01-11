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

type Server struct {
	Addresses []string            // interfaces to use
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

// When communicating with a resolver, we use this structure
// to send packets to it, for sending Error must be nil.
// A resolver responds with a reply packet and a possible error.
// Sending a nil message instructs to resolver to stop.
type DnsMsg struct {
	Dns   *dns.Msg
	Error os.Error
}

// This is a NAMESERVER
// Communicate withit via a channel
// Interface UDPhandler - has function that gets called 
// Interface TCPhandler - has function that gets called
// NewResponder returns a channel, for communication (start/stop)
// caN we use the channel for other stuff??
func (res *Server) NewResponder(h Responder) (ch chan DnsMsg) {
	var port string
	if len(res.Addresses) == 0 {
		// We cannot start responding with an addresss
		return nil
	}
	if res.Port == "" {
		port = "53"
	} else {
		port = res.Port
	}
	// TODO(mg) handle multiple addresses
	switch res.Tcp {
	case true:

	case false:
		udpaddr, _ := net.ResolveUDPAddr(res.Addresses[0] + ":" + port)
		c, _ := net.ListenUDP("udp", udpaddr)
                m := make([]byte, 4096)
                n, raddr, err := c.ReadFrom(m)
                if err != nil {
                        //continue
                }
                m = m[:n]
                // If I don't pick off the remote addr, but do it in the Go routine
                // I've created a race condition?? TODO(mg)
                h.ResponderUDP(c, raddr, m)
		c.Close()
	}
	return nil
}

// The raw packet
func handlerUDP(c *net.UDPConn, raddr net.Addr, in []byte) {
	// don't care what you've read, just blap a default, but put in the
	// correct Id
        fmt.Printf("handlerUDP called!")

	inmsg := new(dns.Msg)
	inmsg.Unpack(in)
        fmt.Printf("%v\n", inmsg)

	m := new(dns.Msg)
	m.MsgHdr.Id = inmsg.MsgHdr.Id
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
