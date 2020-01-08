package dns

import (
	"net"
	"runtime"
	"time"
)

// LimitReader can be used to limit the intake of new packets. Currently it works by checking the number of
// active goroutines. If we have too many it will refuse any new messages. Note that this check is performed every 100th packet.
//
// LimitReader can be used as a DecorateReader in a server as:
//
//	server := &Server{/* various options */}
//	server.DecorateReader = func(r Reader) Reader { return &LimitReader{Reader: r, MaxGoroutines: 10000} }
//
type LimitReader struct {
	Reader

	// MaxGoroutines is the maxium number of goroutines we're willing to tolerate.
	MaxGoroutines int

	upkts int
	tpkts int
}

func tooMany(max int) bool { return runtime.NumGoroutine() > max }

// ReadUDP implements Reader.
func (r *LimitReader) ReadUDP(conn *net.UDPConn, timeout time.Duration) ([]byte, *SessionUDP, error) {
	m, s, err := r.Reader.ReadUDP(conn, timeout)
	if err != nil {
		return nil, nil, err
	}

	r.upkts++
	if r.upkts%thisManyPackets != 0 {
		return m, s, nil
	}

	if tooMany(r.MaxGoroutines) {
		err = refusePacketUDP(conn, m, s)
		return m, s, err
	}
	return m, s, nil
}

// ReadTCP implements Reader.
func (r *LimitReader) ReadTCP(conn net.Conn, timeout time.Duration) ([]byte, error) {
	m, err := r.Reader.ReadTCP(conn, timeout)
	if err != nil {
		return nil, err
	}

	r.tpkts++
	if r.tpkts%100 != 0 {
		return m, nil
	}

	if tooMany(r.MaxGoroutines) {
		err = refusePacketTCP(conn, m)
		return m, err
	}
	return m, nil
}

// ErrPacketRefuse is an error that is returned when a packet is refused by the server.
var ErrPacketRefuse = refuseError{}

type refuseError struct{}

// These implement the net.Error interface.
func (refuseError) Error() string   { return "dns: refusing packet" }
func (refuseError) Timeout() bool   { return false }
func (refuseError) Temporary() bool { return true }

func refusePacketUDP(conn *net.UDPConn, m []byte, s *SessionUDP) error {
	dh, _, err := unpackMsgHdr(m, 0)
	if err != nil {
		return nil
	}

	msg := new(Msg)
	msg.setHdr(dh)
	msg.Rcode = RcodeRefused

	m, err = msg.Pack()
	if err != nil {
		return err
	}

	_, err = WriteToSessionUDP(conn, m, s)
	return err
}

func refusePacketTCP(conn net.Conn, m []byte) error {
	dh, _, err := unpackMsgHdr(m, 0)
	if err != nil {
		return nil
	}

	msg := new(Msg)
	msg.setHdr(dh)
	msg.Rcode = RcodeRefused

	m, err = msg.Pack()
	if err != nil {
		return err
	}

	_, err = conn.Write(m)
	return err
}

const thisManyPackets = 100
