// +build !go1.11 !aix,!darwin,!dragonfly,!freebsd,!linux,!netbsd,!openbsd

package dns

import "net"

const supportsReusePort = false

func listenTCP(network, addr string, options SocketOption) (net.Listener, error) {
	if options != SocketNone {
		// TODO(tmthrgd): return an error?
	}

	return net.Listen(network, addr)
}

func listenUDP(network, addr string, options SocketOption) (net.PacketConn, error) {
	if options != SocketNone {
		// TODO(tmthrgd): return an error?
	}

	return net.ListenPacket(network, addr)
}
