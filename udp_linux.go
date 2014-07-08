// +build linux

package dns

import (
	"net"
	"syscall"
)

// Linux implementation for preparing the socket for sessions
// Based on http://stackoverflow.com/questions/3062205/setting-the-source-ip-for-a-udp-socket
// and http://blog.powerdns.com/2012/10/08/on-binding-datagram-udp-sockets-to-the-any-addresses/
func udpPatchSocketTypes(conn *net.UDPConn, ipv4, ipv6 bool) (err error) {
	file, err := conn.File()
	if err != nil {
		return
	}

	if ipv4 {
		// socket supports IPv4

		err = syscall.SetsockoptInt(int(file.Fd()), syscall.IPPROTO_IP, syscall.IP_PKTINFO, 1)
		if err != nil {
			return err
		}
	}

	if ipv6 {
		// socket supports IPv6

		err = syscall.SetsockoptInt(int(file.Fd()), syscall.IPPROTO_IPV6, syscall.IPV6_RECVPKTINFO, 1)
		if err != nil {
			return err
		}
	}

	return nil
}
