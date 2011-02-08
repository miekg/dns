// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS server implementation

// Package responder implements a DNS server. Any nameserver needs to implement
// the Responder interface to get things going. Each incoming query is handled
// in a seperate goroutine.
// 
// Typical usage of the package:
//
//         type myserv Server
//         func (s *myserv) ResponderUDP(c *net.UDPConn, a net.Addr, in []byte) { /* UDP reply */ }
//         func (s *myserv) ResponderTCP(c *net.TCPConn, in []byte) { /* TCP reply */}
//
//         s := new(Server)             // create new sever
//         s.Address = "127.0.0.1"      // listen address
//         s.Port = "8053"              // listen port
//         var m *myserv                       
//         ch :=make(chan bool)
//         go s.NewResponder(m, ch)     // start the responder
package dns

import (
	"os"
	"net"
)

// Every nameserver implements the Hander interface. It defines
// the kind of nameserver
type Handler interface {
	// Receives the raw message content and writes back 
	// an UDP response. An UDP connection needs a remote
	// address to write to. ServeUDP() must take care of sending
	// any response back to the requestor.
	ServeUDP(c *net.UDPConn, a net.Addr, in []byte)
	// Receives the raw message content and writes back
	// a TCP response. A TCP connection does need to
	// know explicitly be told the remote address. ServeTCP() must
	// take care of sending back a response to the requestor.
	ServeTCP(c *net.TCPConn, in []byte)
}

func ServeUDP(l *net.UDPConn, handler Handler) os.Error {
        if handler == nil {
                // handler == DefaultServer
        }
	for {
		m := make([]byte, DefaultMsgSize) // TODO(mg) out of this loop?
		n, radd, err := l.ReadFromUDP(m)
		if err != nil {
			return err
		}
		m = m[:n]
                go handler.ServeUDP(l, radd, m)
	}
        panic("not reached")
}

func ServeTCP(l *net.TCPListener, handler Handler) os.Error {
        if handler == nil {
        //        handler = DefaultServer
        }
        for {
		b := make([]byte, 2) // receiver length
		c, err := l.AcceptTCP()
		if err != nil {
			return err
		}

		n, cerr := c.Read(b)
		if cerr != nil {
			return cerr
		}
		length := uint16(b[0])<<8 | uint16(b[1])
		if length == 0 {
			return &Error{Error: "received nil msg length"}
		}
		m := make([]byte, length)

		n, cerr = c.Read(m)
		if cerr != nil {
                        return cerr
		}
		i := n
		if i < int(length) {
			n, err = c.Read(m[i:])
			if err != nil {
				return err
			}
			i += n
		}
                go handler.ServeTCP(c, m)
        }
        panic("not reached")
}

func ListenAndServeTCP(addr string, handler Handler) os.Error {
        ta, err := net.ResolveTCPAddr(addr)
        if err != nil {
                return err
        }
        l, err := net.ListenTCP("tcp", ta)
        if err != nil {
                return err
        }
        err = ServeTCP(l, handler)
        l.Close()
        return err
}

func ListenAndServeUDP(addr string, handler Handler) os.Error {
        ua, err := net.ResolveUDPAddr(addr)
        if err != nil {
                return err
        }
        l, err := net.ListenUDP("udp", ua)
        if err != nil {
                return err
        }
        err = ServeUDP(l, handler)
        l.Close()
        return err
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
