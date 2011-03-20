// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS server implementation

package dns

import (
	"os"
	"net"
)

// For both -> logging

func ServeUDP(l *net.UDPConn, f func(*Conn, *Msg)) os.Error {
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

		msg := new(Msg)
		if !msg.Unpack(m) {
			continue
		}
		go f(d, msg)
	}
	panic("not reached")
}

func ServeTCP(l *net.TCPListener, f func(*Conn, *Msg)) os.Error {
	for {
		c, e := l.AcceptTCP()
		if e != nil {
			return e
		}
                d := new(Conn)
                d.TCP = c
                d.Addr = c.RemoteAddr()

                m := make([]byte, MaxMsgSize)  // This may start to hurt someday.
                n, e := d.Read(m)
                if e != nil {
                        continue
                }
                m = m[:n]

		msg := new(Msg)
		if !msg.Unpack(m) {
                        // Logging??
			continue
		}
		go f(d, msg)
	}
	panic("not reached")
}

func ListenAndServeTCP(addr string, f func(*Conn, *Msg)) os.Error {
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

func ListenAndServeUDP(addr string, f func(*Conn, *Msg)) os.Error {
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
