// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS server implementation

package dns

import (
	"os"
	"net"
)

// Do I want this
type Server struct {
	ServeUDP func(*net.UDPConn, net.Addr, *Msg) os.Error
	ServeTCP func(*net.TCPConn, net.Addr, *Msg) os.Error
        /* notify stuff here? */
        /* tsig here */
}

func ServeUDP(l *net.UDPConn, f func(*net.UDPConn, net.Addr, *Msg)) os.Error {
	for {
		m := make([]byte, DefaultMsgSize)
		n, radd, e := l.ReadFromUDP(m)
		if e != nil {
			continue
		}
		m = m[:n]
		msg := new(Msg)
		if !msg.Unpack(m) {
			continue
		}
		go f(l, radd, msg)
	}
	panic("not reached")
}

func ServeTCP(l *net.TCPListener, f func(*net.TCPConn, net.Addr, *Msg)) os.Error {
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
		msg := new(Msg)
		if !msg.Unpack(m) {
			continue
		}
		go f(c, c.RemoteAddr(), msg)
	}
	panic("not reached")
}

func ListenAndServeTCP(addr string, f func(*net.TCPConn, net.Addr, *Msg)) os.Error {
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

func ListenAndServeUDP(addr string, f func(*net.UDPConn, net.Addr, *Msg)) os.Error {
	a, err := net.ResolveUDPAddr(addr)
	if err != nil {
		return err
	}
	l, err := net.ListenUDP("udp", a)
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
	n, err := c.Write(l)
	if err != nil {
		return err
	}
	// And the the message
	n, err = c.Write(m)
	if err != nil {
		return err
	}
	i := n
	for i < len(m) {
		n, err = c.Write(m)
		if err != nil {
			return err
		}
		i += n
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
