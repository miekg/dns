// +build !linux

package dns

import (
	"net"
)

func udpSocketOobData(conn *net.UDPConn) (err error) {
	return
}
