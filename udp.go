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
	sa, err := getUDPSocketName(conn)
	if err != nil {
		return err
	}
	switch sa.(type) {
	case *syscall.SockaddrInet6:
		v6only, err := getUDPSocketOptions6Only(conn)
		if err != nil {
			return err
		}
		setUDPSocketOptions6(conn)
		if !v6only {
			setUDPSocketOptions4(conn)
		}
	case *syscall.SockaddrInet4:
		setUDPSocketOptions4(conn)
	}
	return nil
}
