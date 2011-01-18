// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS server implementation

// Package responder implements a DNS server. Any nameserver needs to implement
// the Responder interface to get things going.
// 
// Typical usage of the package:
//
// type myserv Server
// func (s *myserv) ResponderUDP(c *net.UDPConn, a net.Addr, in []byte) { /* UDP reply */ }
// func (s *myserv) ResponderTCP(c *net.TCPConn, in []byte) { /* TCP reply */}
//
// s := new(Server)             // create new sever
// s.Address = "127.0.0.1"      // listen address
// s.Port = "8053"              // listen port
// var m *myserv                       
// ch :=make(chan bool)
// go s.NewResponder(m, ch)     // start the responder
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
	udp  *net.UDPConn // udp conn
	tcp  *net.TCPConn // tcp conn
	addr net.Addr     // remote address
	msg  []byte       // raw dns message
	err  os.Error     // any errors
}

// Every nameserver implements the Responder interface. It defines
// the kind of nameserver
type Responder interface {
	// Receives the raw message content and writes back 
	// an UDP response. An UDP connection needs a remote
	// address to write to. ResponderUDP() must take care of sending
	// any response back to the requestor.
	ResponderUDP(c *net.UDPConn, a net.Addr, in []byte)
	// Receives the raw message content and writes back
	// a TCP response. A TCP connection does need to
	// know explicitly be told the remote address. ResponderTCP() must
	// take care of sending back a response to the requestor.
	ResponderTCP(c *net.TCPConn, in []byte)
}

// Start a new responder. The returned channel is only used to stop the responder.
// Send 'true' to make it stop
func (res *Server) NewResponder(h Responder, stop chan bool) os.Error {
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
		lch := make(chan *net.TCPListener)
		a, _ := net.ResolveTCPAddr(res.Address + ":" + port)
		go listenerTCP(a, tch, lch)
		listener := <-lch
		// if nil?? TODO(mg)
	foreverTCP:
		for {
			select {
			case <-stop:
				stop <- true
				listener.Close()
				close(stop)
				break foreverTCP
			case s := <-tch:
				if s.err != nil {
					// always fatal??
					println(s.err.String())
					close(stop)
					return s.err
				} else {
					go h.ResponderTCP(s.tcp, s.msg)
				}
			}
		}

	case false:
		uch := make(chan msg)
		a, _ := net.ResolveUDPAddr(res.Address + ":" + port)
		go listenerUDP(a, uch)
	foreverUDP:
		for {
			select {
			case <-stop:
				stop <- true
				close(stop)
				break foreverUDP
			case s := <-uch:
				if s.err != nil {
					//continue
					println(s.err.String())
					close(stop)
					return s.err
				} else {
					go h.ResponderUDP(s.udp, s.addr, s.msg)
				}
			}
		}
	}
	return nil
}

// Listen for UDP requests.
func listenerUDP(a *net.UDPAddr, ch chan msg) {
	c, err := net.ListenUDP("udp", a)
	if err != nil {
		ch <- msg{err: err}
		return
	}
	for {
		m := make([]byte, dns.DefaultMsgSize) // TODO(mg) out of this loop?
		n, radd, err := c.ReadFromUDP(m)
		if err != nil {
			ch <- msg{err: err}
			continue
		}
		m = m[:n]
		// if closed(ch) c.Close() TODO(mg)?? 
		ch <- msg{udp: c, addr: radd, msg: m}
	}
}

// Listen for TCP requests.
// How do I close this ?? TODO(mg)
func listenerTCP(a *net.TCPAddr, ch chan msg, listen chan *net.TCPListener) {
	t, err := net.ListenTCP("tcp", a)
	if err != nil {
		ch <- msg{err: err}
		listen <- nil
		return
	}
	listen <- t // sent listener back (for closing it)
	for {
		l := make([]byte, 2) // receiver length
		c, err := t.AcceptTCP()
		if err != nil {
			ch <- msg{err: err}
		}

		n, cerr := c.Read(l)
		if cerr != nil {
			ch <- msg{err: cerr}
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
		ch <- msg{tcp: c, msg: m}
	}
}

// Send a buffer on the TCP connection.
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

// Send a buffer to the remove address. Only here because
// of the symmetry with SendTCP().
func SendUDP(m []byte, c *net.UDPConn, a net.Addr) os.Error {
	_, err := c.WriteTo(m, a)
	if err != nil {
		return err
	}
	return nil
}

/*
// Basic implementation of a reflector nameserver which responds
// to queries for A types and replies with the qname as the ownername
// and querier's IP as the rdata
type reflectServer Server
func (s *reflectServer) ResponderUDP(c *net.UDPConn, a net.Addr, in []byte) {
        o, ok := makePkt(a, in)
        if ok {
                out, ok1 := o.Pack()
                if ok1 {
                        SendUDP(out, c, a)
                }
        }
}

func (s *reflectServer) ResponderTCP(c *net.TCPConn, in []byte) {
        o, ok := makePkt(c.RemoteAddr(), in)
        if ok {
                out, ok1 := o.Pack()
                if ok1 {
                        SendTCP(out, c)
                }
        }
}

func makePkt(a net.Addr, i []byte) (*dns.Msg, bool) {
        msg := new(dns.Msg)
        if !msg.Unpack(i) {
                return nil, false
        }
        if msg.MsgHdr.Response == true {
                return nil, false
        }
        m := new(dns.Msg)
        m.MsgHdr.Id = msg.MsgHdr.Id
        m.MsgHdr.Authoritative = true
        m.MsgHdr.Response = true
        m.MsgHdr.Opcode = dns.OpcodeQuery
        m.MsgHdr.Rcode = dns.RcodeSuccess
        m.Question = make([]dns.Question, 1)
        m.Question[0] = msg.Question[0]
        if msg.Question[0].Qtype != dns.TypeA {
                // wrong question
                m.MsgHdr.Rcode = dns.RcodeFormatError
                return m ,true
        }
        m.Answer = make([]dns.RR, 1)
        r := new(dns.RR_A)
        r.Hdr = dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}
        ip, _ := net.ResolveUDPAddr(a.String())
        r.A = ip.IP.To4()
        m.Answer[0] = r
        return m, true
}

// A simple nameserver implementation. It reponds to queries for the A record and replies
// with the qname as the ownername and the rdata of the A record set to the senders address.
//
// Sample (udp) usage:
// stop := make(chan bool)
// s    := new(Server)
// go s.NewResponder(Reflector, stop)
var Reflector *reflectServer

What point is there to Export this?
*/
