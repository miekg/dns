// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"net"
	"syscall"
)

type UDPSession struct {
	raddr   *net.UDPAddr
	context []byte
}

func (session *UDPSession) RemoteAddr() net.Addr {
	return session.raddr
}

// UDPConn wrap a net.UDPConn with dns.UDPConn struct
type UDPConn struct {
	*net.UDPConn
}

// NewUDPConn return a new UDPConn.
// Initialize the underlying net.UDPConn for supporting "sessions"
// Sessions solve https://github.com/miekg/dns/issues/95
func NewUDPConn(conn *net.UDPConn) (*UDPConn, error) {
	// this function is implemented on a per platform basis. See udp_*.go for more details
	conn := new(net.UDPConn)
	file, err := conn.File()
	if err != nil {
		return
	}

	sa, err := syscall.Getsockname(int(file.Fd()))
	switch sa.(type) {
	case *syscall.SockaddrInet6:
		// dual stack. See http://stackoverflow.com/questions/1618240/how-to-support-both-ipv4-and-ipv6-connections
		v6only, err := syscall.GetsockoptInt(int(file.Fd()), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY)
		if err != nil {
			return err
		}
		SetUDPSocketOptions6(conn)

		if v6only == 0 {
			SetUDPSocketOptions4(conn)
		}
	case *syscall.SockaddrInet4:
		SetUDPSocketOptions4(conn)
	}
	return &UDPConn{conn}, nil
}

// ReadFromSessionUDP ... Just like net.UDPConn.ReadFrom(), but returns a session object instead of net.UDPAddr
// (RemoteAddr() is available from the UDPSession object)
func (conn *UDPConn) ReadFromSessionUDP(b []byte) (int, *UDPSession, error) {
	oob := make([]byte, 40)
	n, oobn, _, raddr, err := conn.ReadMsgUDP(b, oob)
	if err != nil {
		return
	}

	session := &UDPSession{raddr, oob[:oobn]}
	return n, session, err
}

// WriteToSessionUDP Just like net.UDPConn.WritetTo(), but uses a session object instead of net.Addr
func (conn *UDPConn) WriteToSessionUDP(b []byte, session *UDPSession) (int, error) {
	n, _, err = conn.WriteMsgUDP(b, session.context, session.raddr)
	return n, err
}
