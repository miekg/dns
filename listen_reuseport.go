// +build go1.11
// +build aix darwin dragonfly freebsd linux netbsd openbsd

package dns

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

const supportsReusePort = true

func reuseportAndIptransparentControl(network, address string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}
	if opErr != nil {
		return opErr
	}
	err = c.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
	})
	if err != nil {
		return err
	}

	return opErr
}

func reuseportControl(network, address string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}

	return opErr
}

func iptransparentControl(network, address string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
	})
	if err != nil {
		return err
	}

	return opErr
}

func listenTCP(network, addr string, options SocketOption) (net.Listener, error) {
	var lc net.ListenConfig
	if options&SocketReusePort > 0 && options&SocketIpTransparent > 0 {
		lc.Control = reuseportAndIptransparentControl
	} else if options&SocketReusePort > 0 {
		lc.Control = reuseportControl
	} else if options&SocketIpTransparent > 0 {
		lc.Control = iptransparentControl
	}

	return lc.Listen(context.Background(), network, addr)
}

func listenUDP(network, addr string, options SocketOption) (net.PacketConn, error) {
	var lc net.ListenConfig
	if options&SocketReusePort > 0 && options&SocketIpTransparent > 0 {
		lc.Control = reuseportAndIptransparentControl
	} else if options&SocketReusePort > 0 {
		lc.Control = reuseportControl
	} else if options&SocketIpTransparent > 0 {
		lc.Control = iptransparentControl
	}

	return lc.ListenPacket(context.Background(), network, addr)
}
