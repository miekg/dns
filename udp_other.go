// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !linux

package dns

import (
	"net"
)

// These do nothing. See udp_linux.go for an example of how to implement this.

// We tried to adhire to some kind of naming scheme.

func setUDPSocketOptions4(conn *net.UDPConn) error                { return nil }
func setUDPSocketOptions6(conn *net.UDPConn) error                { return nil }
func getUDPSocketOptions6Only(conn *net.UDPConn) (bool, error)    { return false, nil }
func getUDPSocketName(conn *net.UDPConn) (syscal.Sockaddr, error) { return nil, nil }
