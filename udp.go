package dns

import (
	"net"
)

type UDPSession struct {
	raddr   *net.UDPAddr
	context []byte
}

func (session *UDPSession) RemoteAddr() net.Addr {
	return session.raddr
}

type UDPConn struct {
	*net.UDPConn
}

// Wrap a net.UDPConn with dns.UDPConn struct
// Initialize the underlying net.UDPConn for supporting "sessions"
// Sessions solve https://github.com/miekg/dns/issues/95
func NewUDPConn(conn *net.UDPConn) (newconn *UDPConn, err error) {
	// this function is implemented on a per platform basis. See udp_*.go for more details
	err = udpSocketOobData(conn)

	if err != nil {
		return
	}

	return &UDPConn{conn}, nil
}

// Just like net.UDPConn.ReadFrom(), but returns a session object instead of net.UDPAddr
// (RemoteAddr() is available from the UDPSession object)
func (conn *UDPConn) ReadFromSessionUDP(b []byte) (n int, session *UDPSession, err error) {
	oob := make([]byte, 40)

	n, oobn, _, raddr, err := conn.ReadMsgUDP(b, oob)
	if err != nil {
		return
	}

	session = &UDPSession{raddr, oob[:oobn]}

	return
}

// Just like net.UDPConn.WritetTo(), but uses a session object instead of net.Addr
func (conn *UDPConn) WriteToSessionUDP(b []byte, session *UDPSession) (n int, err error) {
	n, _, err = conn.WriteMsgUDP(b, session.context, session.raddr)
	return
}
