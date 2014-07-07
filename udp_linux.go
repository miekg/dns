// +build linux

package dns

import (
	"net"
	"syscall"
)

func udpSocketOobData(conn *net.UDPConn) (err error) {
	file, err := conn.File()
	if err != nil {
		return
	}

	err = syscall.SetsockoptInt(int(file.Fd()), syscall.IPPROTO_IP, syscall.IP_PKTINFO, 1)

	return
}
