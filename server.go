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

func accepterUDP(l *net.UDPConn, ch chan *Request, quit chan bool) {
	for {
		select {
		case <-quit:
			return
		default:
			r := new(Request)
			r.Tcp = false
			m := make([]byte, DefaultMsgSize)
			n, radd, err := l.ReadFromUDP(m)
			if err != nil {
				r.Error = err
				ch <- r
				continue
			}
			m = m[:n]
			r.Buf = m
			r.Addr = radd
			r.UDPConn = l
			ch <- r
		}
	}
	panic("not reached")
}

func accepterTCP(l *net.TCPListener, ch chan *Request, quit chan bool) {
        b := make([]byte, 2)
	for {
		select {
		case <-quit:
			return
		default:
			r := new(Request)
			r.Tcp = true
			c, err := l.AcceptTCP()
			if err != nil {
				r.Error = err
				ch <- r
				continue
			}
			n, cerr := c.Read(b)
			if cerr != nil {
				r.Error = cerr
				ch <- r
				continue
			}

			length := uint16(b[0])<<8 | uint16(b[1])
			if length == 0 {
				r.Error = &Error{Error: "received nil msg length"}
				ch <- r
			}
			m := make([]byte, length)

			n, cerr = c.Read(m)
			if cerr != nil {
				r.Error = cerr
				ch <- r
				continue
			}
			i := n
			if i < int(length) {
				n, err = c.Read(m[i:])
				if err != nil {
					r.Error = err
					ch <- r
				}
				i += n
			}
			r.Buf = m
			r.Addr = c.RemoteAddr()
			r.TCPConn = c
			ch <- r
		}
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
//         go dns.ListenAndServe("127.0.0.1:8053", m, ch)
//         m <- true                    // stop the goroutine
func ListenAndServe(addr string, handler Handler, q chan bool) os.Error {
	ta, err := net.ResolveTCPAddr(addr)
	if err != nil {
		return err
	}
	lt, err := net.ListenTCP("tcp", ta)
	if err != nil {
		return err
	}

        ua, err := net.ResolveUDPAddr(addr)
        if err != nil {
                return err
        }
	lu, err := net.ListenUDP("udp", ua)
        if err != nil {
                return err
        }

        rc := make(chan *Request)
        qt := make(chan bool)
        qu := make(chan bool)
        go accepterTCP(lt, rc, qt)
        go accepterUDP(lu, rc, qu)

        for {
                select {
                case <-q:
                        /* quit received, lets stop */
                        lt.Close()
                        lu.Close()
                        qt <- true
                        qu <- true
                case r:=<-rc:
                        /* request recieved */
                        if r.Tcp {
                                go handler.ReplyTCP(r.TCPConn, r.Addr, r.Buf)
                        } else {
                                go handler.ReplyUDP(r.UDPConn, r.Addr, r.Buf)
                        }
                }
        }
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
