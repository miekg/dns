// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS server implementation

// Package responder implements a DNS server. A nameserver needs to implement
// the Responder interface:
//
// type myserv Server
// func (s *myserv) ResponderUDP(c *net.UDPConn, a net.Addr, in []byte) { /* UDP reply */ }
// func (s *myserv) ResponderTCP(c *net.TCPConn, in []byte) { /* TCP reply */}
// su := new(Server)                    // create new sever
// su.Address = "127.0.0.1"             // listen address
// su.Port = "8053"                     // listen port
// var us *myserv                       
// uch :=make(chan bool)
// go su.NewResponder(us, uch)          // start the responder
package responder

import (
	"os"
	"net"
	"dns"
)

// Options for a nameserver.
type Server struct {
	Address string // interface to use, for multiple interfaces, use multiple servers
	Port    string // what port to use
	Timeout int    // seconds before giving up on packet
	Tcp     bool   // use TCP
}

type msg struct {
	cu   *net.UDPConn // udp conn
	ct   *net.TCPConn // tcp conn
	addr net.Addr     // remote address
	msg  []byte       // raw dns message
	err  os.Error     // any errors
}

// Every nameserver implements the Responder interface. It defines
// the kind of nameserver
type Responder interface {
	// Receives the raw message content and writes back 
        // an udp response. An UDP connection needs a remote
        // address to write to.
	ResponderUDP(c *net.UDPConn, a net.Addr, in []byte)
	// Receives the raw message content and writes back
        // a tcp response. A TCP connection does need to
        // know explicitly be told the remote address.
	ResponderTCP(c *net.TCPConn, in []byte)
}

// Start a new responder. The returned channel is only used
// to stop the responder.
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
		tch := make(chan msg)
		a, _ := net.ResolveTCPAddr(res.Address + ":" + port)
		go listenerTCP(a, tch)
	foreverTCP:
		for {
			select {
			case <-ch:
				ch <- true
				/* stop listening */
				break foreverTCP
			case s := <-tch:
				if s.err != nil {
					//continue
				}
				go h.ResponderTCP(s.ct, s.msg)
			}
		}

	case false:
		uch := make(chan msg)
		a, _ := net.ResolveUDPAddr(res.Address + ":" + port)
		go listenerUDP(a, uch)
	foreverUDP:
		for {
			select {
			case <-ch:
				ch <- true // last echo
				break foreverUDP
			case s := <-uch:
				if s.err != nil {
					//continue
				}
				go h.ResponderUDP(s.cu, s.addr, s.msg)
			}
		}
	}
	return nil
}

func listenerUDP(a *net.UDPAddr, ch chan msg) {
	c, _ := net.ListenUDP("udp", a)
	// check error TODO(mg)
	for {
		m := make([]byte, dns.DefaultMsgSize) // TODO(mg) out of this loop?
		n, radd, err := c.ReadFromUDP(m)
		if err != nil {
			// hmm
		}
		m = m[:n]
		// if closed(ch) c.Close() TODO(mg)
		ch <- msg{cu: c, addr: radd, msg: m}
	}
}

func listenerTCP(a *net.TCPAddr, ch chan msg) {
	t, _ := net.ListenTCP("tcp", a)
	for {
		l := make([]byte, 2) // receiver length
		c, err := t.AcceptTCP()
		var _ = err // handle err TODO(mg)

		n, cerr := c.Read(l)
		if err != nil {
			// Send err mesg
		}
		length := uint16(l[0])<<8 | uint16(l[1])
		if length == 0 {
			// Send err mesg
			//return nil, &dns.Error{Error: "received nil msg length", Server: c.RemoteAddr(
		}

		m := make([]byte, length)

		n, cerr = c.Read(m)
		if cerr != nil {
			//send msg  TODO(mg)
			//return nil, cerr
		}
		i := n
		if i < int(length) {
			n, err = c.Read(m[i:])
			if err != nil {
				//send err
				//return nil, err
			}
			i += n
		}
		ch <- msg{ct: c, msg: m}
	}
}

// Send a buffer on the TCP connection
func SendTCP(m []byte, c *net.TCPConn) os.Error {
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

// Small helper function to help sending UDP packets. Mostly
// done for the symmetry. see SendTCP.
func SendUDP(m []byte, c *net.UDPConn, a net.Addr) os.Error {
	_, err := c.WriteTo(m, a)
	if err != nil {
		return err
	}
	return nil
}
