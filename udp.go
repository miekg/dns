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

func NewUDPConn(conn *net.UDPConn) (newconn *UDPConn, err error) {
	err = udpSocketOobData(conn)
	if err != nil {
		return
	}

	return &UDPConn{conn}, nil
}

func (conn *UDPConn) ReadFromSessionUDP(b []byte) (n int, session *UDPSession, err error) {
	oob := make([]byte, 1024)

	n, oobn, _, raddr, err := conn.ReadMsgUDP(b, oob)
	if err != nil {
		return
	}

	session = &UDPSession{raddr, oob[:oobn]}

	return
}

func (conn *UDPConn) WriteToSessionUDP(b []byte, session *UDPSession) (n int, err error) {
	n, _, err = conn.WriteMsgUDP(b, session.context, session.raddr)
	return
}
