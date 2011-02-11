// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS server implementation

package dns

import (
	"os"
	"net"
)

type Server int                 // Doesn't really matter

// Wrap request in this struct
type Request struct {
	Tcp     bool         // True for tcp, false for udp
	Buf     []byte       // The received message
	Addr    net.Addr     // Remote site
	UDPConn *net.UDPConn // Connection for UDP
	TCPConn *net.TCPConn // Connection for TCP
	Error   os.Error     // Any errors that are found
}

// Every nameserver implements the Hander interface. It defines
// the kind of nameserver
type Handler interface {
	// Receives the raw message content and writes back 
	// an UDP response. An UDP connection needs a remote
	// address to write to. ServeUDP() must take care of sending
	// any response back to the requestor.
	ReplyUDP(c *net.UDPConn, a net.Addr, in []byte)
	// Receives the raw message content and writes back
	// a TCP response. A TCP connection does need to
	// know explicitly be told the remote address. ServeTCP() must
	// take care of sending back a response to the requestor.
	ReplyTCP(c *net.TCPConn, a net.Addr, in []byte)
}

func ServeUDP(l *net.UDPConn, f func(*net.UDPConn, net.Addr, []byte)) os.Error {
	for {
                m := make([]byte, DefaultMsgSize)
                n, radd, e := l.ReadFromUDP(m)
                if e != nil {
                        continue
                }
                m = m[:n]
                go f(l, radd, m)
	}
	panic("not reached")
}

func ServeTCP(l *net.TCPListener, f func(*net.TCPConn, net.Addr, []byte)) os.Error {
        b := make([]byte, 2)
	for {
                c, e := l.AcceptTCP()
	        if e != nil {
                        return e
                }
		n, e := c.Read(b)
		if e != nil {
                        continue
		}

		length := uint16(b[0])<<8 | uint16(b[1])
		if length == 0 {
		        return &Error{Error: "received nil msg length"}
		}
                m := make([]byte, length)

	        n, e = c.Read(m)
		if e != nil {
		        continue
		}
		i := n
		if i < int(length) {
		        n, e = c.Read(m[i:])
		        if e != nil {
                                continue
			}
			i += n
		}
                go f(c, c.RemoteAddr(), m)
	}
	panic("not reached")
}

// This function implements a nameserver. It should be run as a goroutines.
// The function itself starts two new goroutines (one for TCP and one for UDP)
// and for each incoming message run the ReplyTCP or ReplyUCP again as a 
// goroutine.
// 
// Typical usage of ListenAndServe:
//
//         type myserv dns.Server
//         func (s *myserv) ReplyUDP(c *net.UDPConn, a net.Addr, in []byte) { 
//              /* UDP reply */ 
//         }
//         func (s *myserv) ReplyTCP(c *net.TCPConn, a net.Addr, in []byte) {
//              /* TCP reply */
//         }
//
//         var m *myserv                       
//         ch := make(chan bool)
//         dns.ListenAndServe("127.0.0.1:8053", m, ch)
//         m <- true                    // stop the goroutine
func ListenAndServeTCP(addr string, f func(*net.TCPConn, net.Addr, []byte)) os.Error {
	a, err := net.ResolveTCPAddr(addr)
	if err != nil {
		return err
	}
	l, err := net.ListenTCP("tcp", a)
	if err != nil {
		return err
	}
        err = ServeTCP(l, f)
	return err
}

func ListenAndServeUDP(addr string, f func(*net.UDPConn, net.Addr, []byte)) os.Error {
	a, err := net.ResolveUDPAddr(addr)
	if err != nil {
		return err
	}
	l, err := net.ListenUDP("tcp", a)
	if err != nil {
		return err
	}
        err = ServeUDP(l, f)
	return err
}

// Send a buffer on the TCP connection.
func SendTCP(m []byte, c *net.TCPConn, a net.Addr) os.Error {
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
