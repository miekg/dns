// +build linux

package dns

import (
	"net"
	"syscall"
)

// Linux implementation for preparing the socket for sessions
// Based on http://stackoverflow.com/questions/3062205/setting-the-source-ip-for-a-udp-socket
// and http://blog.powerdns.com/2012/10/08/on-binding-datagram-udp-sockets-to-the-any-addresses/
func udpSocketOobData(conn *net.UDPConn) (err error) {
	file, err := conn.File()
	if err != nil {
		return
	}

	// IPv4 support
	err = syscall.SetsockoptInt(int(file.Fd()), syscall.IPPROTO_IP, syscall.IP_PKTINFO, 1)
	if err != nil {
		return
	}

	// IPv6 support
	err = syscall.SetsockoptInt(int(file.Fd()), syscall.IPPROTO_IPV6, syscall.IPV6_RECVPKTINFO, 1)

	return
}
