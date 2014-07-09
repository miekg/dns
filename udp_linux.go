// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux

package dns

// See:
// * http://stackoverflow.com/questions/3062205/setting-the-source-ip-for-a-udp-socket and
// * http://blog.powerdns.com/2012/10/08/on-binding-datagram-udp-sockets-to-the-any-addresses/
//
// Why do we need this: When listening on 0.0.0.0 with UDP so kernel decides what is the outgoing
// interface, this might not always be the correct one. This code will make sure the egress
// packet's interface matched the ingress' one.

import (
	"net"
	"syscall"
)

// setUDPSocketOptions4 prepares the v4 socket for sessions.
func setUDPSocketOptions4(conn *net.UDPConn) error {
	// We got the .File() in NewUDPConn, this this will work.
	file, _ := conn.File()
	err := syscall.SetsockoptInt(int(file.Fd()), syscall.IPPROTO_IP, syscall.IP_PKTINFO, 1)
	if err != nil {
		return err
	}
	return nil
}

// setUDPSocketOptions6 prepares the v6 socket for sessions.
func setUDPSocketOptions6(conn *net.UDPConn) error {
	// We got the .File() in NewUDPConn, this this will work.
	file, _ := conn.File()
	err := syscall.SetsockoptInt(int(file.Fd()), syscall.IPPROTO_IPV6, syscall.IPV6_RECVPKTINFO, 1)
	if err != nil {
		return err
	}
	return nil
}
