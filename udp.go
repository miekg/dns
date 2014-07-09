// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"net"
	"syscall"
)

type sessionUDP struct {
	raddr   *net.UDPAddr
	context []byte
}

func (s *sessionUDP) RemoteAddr() net.Addr { return s.raddr }

// setUDPSocketOptions sets the UDP socket options.
// This function is implemented on a per platform basis. See udp_*.go for more details
func setUDPSocketOptions(conn *net.UDPConn) error {
	file, err := conn.File()
	if err != nil {
		return err
	}

	sa, err := syscall.Getsockname(int(file.Fd()))
	switch sa.(type) {
	case *syscall.SockaddrInet6:
		// dual stack. See http://stackoverflow.com/questions/1618240/how-to-support-both-ipv4-and-ipv6-connections
		v6only, err := syscall.GetsockoptInt(int(file.Fd()), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY)
		if err != nil {
			return err
		}
		setUDPSocketOptions6(conn)
		if v6only == 0 {
			setUDPSocketOptions4(conn)
		}
	case *syscall.SockaddrInet4:
		setUDPSocketOptions4(conn)
	}
	return nil
}

// readFromSessionUDP acts just like net.UDPConn.ReadFrom(), but returns a session object instead of a
// net.UDPAddr.
func readFromSessionUDP(conn *net.UDPConn, b []byte) (int, *sessionUDP, error) {
	oob := make([]byte, 40)
	n, oobn, _, raddr, err := conn.ReadMsgUDP(b, oob)
	if err != nil {
		return n, nil, err
	}
	session := &sessionUDP{raddr, oob[:oobn]}
	return n, session, err
}

// writeToSessionUDP acts just like net.UDPConn.WritetTo(), but uses a *sessionUDP instead of a net.Addr.
func writeToSessionUDP(conn *net.UDPConn, b []byte, session *sessionUDP) (int, error) {
	n, _, err := conn.WriteMsgUDP(b, session.context, session.raddr)
	return n, err
}
