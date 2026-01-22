package dns

import "net"

// Session captures per-packet metadata for UDP traffic handled by ResponseWriter.
type Session struct {
	Addr *net.UDPAddr
	OOB  []byte
}

// SessionUDP is kept for backward compatibility with older code.
type SessionUDP = Session
