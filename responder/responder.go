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
)

type Server struct {
	Address string              // interface to use, for multiple interfaces, use multiple servers
	Port    string              // what port to use
	Timeout int                 // seconds before giving up on packet
	Tcp     bool                // use TCP
	Mangle  func([]byte) []byte // mangle the packet, before sending
}

type MsgUDP struct {
	c    *net.UDPConn // connection
	addr *net.UDPAddr // remote address
	msg  []byte       // raw dns message
	err  os.Error     // any errors
}

type MsgTCP struct {
	c   *net.TCPConn // connection
	msg []byte       // raw dns message
	err os.Error     // any errors
}

// Every nameserver must implement the Handler interface.
type Responder interface {
	// Receives the raw message content
	ResponderUDP(c *net.UDPConn, a *net.UDPAddr, in []byte)
	// Receives the raw message content
	ResponderTCP(c *net.TCPConn, in []byte)
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
		tch := make(chan MsgTCP)
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
				go h.ResponderTCP(s.c, s.msg)
			}
		}

	case false:
		uch := make(chan MsgUDP)
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
				go h.ResponderUDP(s.c, s.addr, s.msg)
			}
		}
	}
	return nil
}

func listenerUDP(a *net.UDPAddr, ch chan MsgUDP) {
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
		ch <- MsgUDP{c, radd, m, nil}
	}
}

func listenerTCP(a *net.TCPAddr, ch chan MsgTCP) {
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
		ch <- MsgTCP{c, m, nil}
	}
}

// Send a raw msg over a TCP connection
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

// if we do tcp we should also provide an udp version
// First the message TODO(mg)
func SendUDP(m []byte, c *net.UDPConn, a *net.UDPAddr) os.Error {
	_, err := c.WriteTo(m, a)
	if err != nil {
		return err
	}
	return nil
}
