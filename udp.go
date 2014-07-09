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

type UDPConn struct {
	*net.UDPConn
}

// Wrap a net.UDPConn with dns.UDPConn struct
// Initialize the underlying net.UDPConn for supporting "sessions"
// Sessions solve https://github.com/miekg/dns/issues/95
func NewUDPConn(conn *net.UDPConn) (newconn *UDPConn, err error) {
	// this function is implemented on a per platform basis. See udp_*.go for more details
	err = udpPatchSocket(conn)

	if err != nil {
		return
	}

	return &UDPConn{conn}, nil
}

// Just like net.UDPConn.ReadFrom(), but returns a session object instead of net.UDPAddr
// (RemoteAddr() is available from the UDPSession object)
func (conn *UDPConn) ReadFromSessionUDP(b []byte) (n int, session *UDPSession, err error) {
	oob := make([]byte, 40)

	n, oobn, _, raddr, err := conn.ReadMsgUDP(b, oob)
	if err != nil {
		return
	}

	session = &UDPSession{raddr, oob[:oobn]}

	return
}

// Just like net.UDPConn.WritetTo(), but uses a session object instead of net.Addr
func (conn *UDPConn) WriteToSessionUDP(b []byte, session *UDPSession) (n int, err error) {
	n, _, err = conn.WriteMsgUDP(b, session.context, session.raddr)
	return
}

func udpPatchSocket(conn *net.UDPConn) (err error) {
	file, err := conn.File()
	if err != nil {
		return
	}

	sa, err := syscall.Getsockname(int(file.Fd()))

	ipv4, ipv6 := false, false
	switch sa.(type) {
	case *syscall.SockaddrInet6:
		ipv6 = true

		// dual stack. See http://stackoverflow.com/questions/1618240/how-to-support-both-ipv4-and-ipv6-connections
		v6only, err := syscall.GetsockoptInt(int(file.Fd()), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY)
		if err != nil {
			return err
		}

		if v6only == 0 {
			ipv4 = true
		}
	case *syscall.SockaddrInet4:
		ipv4 = true
	}

	return udpPatchSocketTypes(conn, ipv4, ipv6)
}
