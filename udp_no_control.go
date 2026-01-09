//go:build windows || darwin
// +build windows darwin

// TODO(tmthrgd): Remove this Windows-specific code if go.dev/issue/7175 and
//   go.dev/issue/7174 are ever fixed.

// NOTICE(stek29): darwin supports PKTINFO in sendmsg, but it unbinds sockets, see https://github.com/miekg/dns/issues/724

package dns

import "net"

// ReadFromSessionUDP acts just like net.UDPConn.ReadFrom(), but returns a session object instead of a
// net.UDPAddr.
func ReadFromSessionUDP(conn *net.UDPConn, b []byte) (int, *Session, error) {
	n, raddr, err := conn.ReadFrom(b)
	if err != nil {
		return n, nil, err
	}
	return n, &Session{Addr: raddr.(*net.UDPAddr)}, err
}

// WriteToSessionUDP acts just like net.UDPConn.WriteTo(), but uses a *Session instead of a net.Addr.
func WriteToSessionUDP(conn *net.UDPConn, b []byte, session *Session) (int, error) {
	return conn.WriteTo(b, session.Addr)
}

func setUDPSocketOptions(*net.UDPConn) error { return nil }
func parseDstFromOOB([]byte) net.IP          { return nil }
