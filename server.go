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
// Add tsig stuff as in resolver.go

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
                d.Port = addr.Port       // Why not the same as in dns.go, line 96

		msg := new(Msg)
		if !msg.Unpack(m) {
			continue
		}
		go f(d, msg)
	}
	panic("not reached")
}

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

                m := d.NewBuffer()
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

// config functions Config
// ListenAndServeTCPTsig
// ListenAndServeUDPTsig

func ListenAndServeTCP(addr string, f func(*Conn, *Msg)) os.Error {
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

func ListenAndServeUDP(addr string, f func(*Conn, *Msg)) os.Error {
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
