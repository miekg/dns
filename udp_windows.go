// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows

package dns

import (
	"net"
	"syscall"
)

// readFromSessionUDP acts just like net.UDPConn.ReadFrom(), but returns a session object instead of a
// net.UDPAddr.
func readFromSessionUDP(conn *net.UDPConn, b []byte) (int, *sessionUDP, error) {
	n, raddr, err := conn.ReadFrom(b)
	if err != nil {
		return n, nil, err
	}
	session := &sessionUDP{raddr.(*net.UDPAddr), nil}
	return n, session, err
}

// writeToSessionUDP acts just like net.UDPConn.WritetTo(), but uses a *sessionUDP instead of a net.Addr.
func writeToSessionUDP(conn *net.UDPConn, b []byte, session *sessionUDP) (int, error) {
	n, err := conn.WriteTo(b, session.raddr)
	return n, err
}

// These do nothing. See udp_linux.go for an example of how to implement this.

// We tried to adhire to some kind of naming scheme.

func setUDPSocketOptions4(conn *net.UDPConn) error                 { return nil }
func setUDPSocketOptions6(conn *net.UDPConn) error                 { return nil }
func getUDPSocketOptions6Only(conn *net.UDPConn) (bool, error)     { return false, nil }
func getUDPSocketName(conn *net.UDPConn) (syscall.Sockaddr, error) { return nil, nil }
