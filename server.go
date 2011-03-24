// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS server implementation

package dns

import (
	"os"
	"net"
)

// HandleUDP handles one UDP connection. It reads the incoming
// message and then calls the function f.
// The function f is executed in a seperate goroutine at which point 
// HandleUDP returns.
func HandleUDP(l *net.UDPConn, f func(*Conn, *Msg)) os.Error {
	for {
		m := make([]byte, DefaultMsgSize)
		n, addr, e := l.ReadFromUDP(m)
		if e != nil {
			continue
		}
		m = m[:n]

		d := new(Conn)
		d.UDP = l
		d.Addr = addr
		d.Port = addr.Port

		msg := new(Msg)
		if !msg.Unpack(m) {
			continue
		}
		go f(d, msg)
	}
	panic("not reached")
}

// HandleTCP handles one TCP connection. It reads the incoming
// message and then calls the function f.
// The function f is executed in a seperate goroutine at which point 
// HandleTCP returns.
func HandleTCP(l *net.TCPListener, f func(*Conn, *Msg)) os.Error {
	for {
		c, e := l.AcceptTCP()
		if e != nil {
			return e
		}
		d := new(Conn)
		d.TCP = c
		d.Addr = c.RemoteAddr()
		d.Port = d.TCP.RemoteAddr().(*net.TCPAddr).Port

		msg := new(Msg)
		err := d.ReadMsg(msg)

		if err != nil {
			// Logging??
			continue
		}
		go f(d, msg)
	}
	panic("not reached")
}

// ListenAndServerTCP listens on the TCP network address addr and
// then calls HandleTCP with f to handle requests on incoming
// connections. The function f may not be nil.
func ListenAndServeTCP(addr string, f func(*Conn, *Msg)) os.Error {
	if f == nil {
		return &Error{Error: "The handle function may not be nil"}
	}
	a, err := net.ResolveTCPAddr(addr)
	if err != nil {
		return err
	}
	l, err := net.ListenTCP("tcp", a)
	if err != nil {
		return err
	}
	err = HandleTCP(l, f)
	return err
}

// ListenAndServerUDP listens on the UDP network address addr and
// then calls HandleUDP with f to handle requests on incoming
// connections. The function f may not be nil.
func ListenAndServeUDP(addr string, f func(*Conn, *Msg)) os.Error {
	if f == nil {
		return &Error{Error: "The handle function may not be nil"}
	}
	a, err := net.ResolveUDPAddr(addr)
	if err != nil {
		return err
	}
	l, err := net.ListenUDP("udp", a)
	if err != nil {
		return err
	}
	err = HandleUDP(l, f)
	return err
}
