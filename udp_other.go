// +build !linux

package dns

import (
	"net"
)

// Default implementation for preparing the socket for sessions
// This actually does nothing. See udp_linux.go for an example of how to implement this.
// Make sure you edit the comment on the top of this file accordingly when adding implementations
func udpPatchSocketTypes(conn *net.UDPConn, ipv4, ipv6 bool) (err error) {
	return nil
}
