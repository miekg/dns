// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !linux

package dns

import (
	"net"
)

// These actually do nothing. See udp_linux.go for an example of how to implement this.

func setUDPSocketOptions4(conn *net.UDPConn) error { return nil }
func setUDPSocketOptions6(conn *net.UDPConn) error { return nil }
