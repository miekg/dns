package dns

// A concurrent client implementation. 

import (
	"io"
	"net"
	"time"
)

// Order of events:
// *client -> *reply -> Exchange*() -> dial()/send()->write()/receive()->read()

type reply struct {
	client         *Client
	addr           string
	req            *Msg
	conn           net.Conn
	tsigRequestMAC string
	tsigTimersOnly bool
	tsigStatus     error
	rtt            time.Duration
	t              time.Time
}

// A Client defines parameter for a DNS client. A nil
// Client is usable for sending queries.
type Client struct {
	Net          string            // if "tcp" a TCP query will be initiated, otherwise an UDP one (default is "" for UDP)
	Attempts     int               // number of attempts, if not set defaults to 1
	Retry        bool              // retry with TCP
	ReadTimeout  time.Duration     // the net.Conn.SetReadTimeout value for new connections (ns), defauls to 2 * 1e9
	WriteTimeout time.Duration     // the net.Conn.SetWriteTimeout value for new connections (ns), defauls to 2 * 1e9
	TsigSecret   map[string]string // secret(s) for Tsig map[<zonename>]<base64 secret>, zonename must be fully qualified
}

// Do performs an asynchronous query. The msg *Msg is the question to ask, the 
// string addr is the address of the nameserver, the parameter data is used
// in the callback function. The call backback function is called with the
// original query, the answer returned from the nameserver an optional error and
// data.
func (c *Client) Do(msg *Msg, addr string, data interface{}, callback func(*Msg, *Msg, error, interface{})) {
	go func() {
		r, err := c.Exchange(msg, addr)
		callback(msg, r, err, data)
	}()
}

// DoRtt is equivalent to Do, except that is calls ExchangeRtt.
func (c *Client) DoRtt(msg *Msg, addr string, data interface{}, callback func(*Msg, *Msg, time.Duration, error, interface{})) {
	go func() {
		r, rtt, err := c.ExchangeRtt(msg, addr)
		callback(msg, r, rtt, err, data)
	}()
}

// Exchange performs an synchronous query. It sends the message m to the address
// contained in a and waits for an reply. Basic use pattern with a *Client:
//
//	c := new(dns.Client)
//	in, err := c.Exchange(message, "127.0.0.1:53")
//
// See Client.ExchangeRtt(...) to get the round trip time.
func (c *Client) Exchange(m *Msg, a string) (r *Msg, err error) {
	r, _, err = c.ExchangeRtt(m, a)
	return
}

// ExchangeRtt performs an synchronous query. It sends the message m to the address
// contained in a and waits for an reply. Basic use pattern with a *Client:
//
//	c := new(dns.Client)
//	in, rtt, err := c.ExchangeRtt(message, "127.0.0.1:53")
// 
func (c *Client) ExchangeRtt(m *Msg, a string) (r *Msg, rtt time.Duration, err error) {
	w := new(reply)
	w.client = c
	w.addr = a
	if err = w.dial(); err != nil {
		return nil, 0, err
	}
	if err = w.send(m); err != nil {
		return nil, 0, err
	}
	r, err = w.receive()
	return r, w.rtt, err
}

func (w *reply) RemoteAddr() net.Addr {
	if w.conn != nil {
		return w.conn.RemoteAddr()
	}
	return nil
}

// dial connects to the address addr for the network set in c.Net
func (w *reply) dial() (err error) {
	var conn net.Conn
	attempts := w.client.Attempts
	if attempts == 0 {
		attempts = 1
	}
	for a := 0; a < attempts; a++ {
		if w.client.Net == "" {
			conn, err = net.Dial("udp", w.addr)
		} else {
			conn, err = net.Dial(w.client.Net, w.addr)
		}
		if err != nil {
			// There are no timeouts defined?
			continue
		}
	}
	w.conn = conn
	return
}

func (w *reply) receive() (*Msg, error) {
	var p []byte
	m := new(Msg)
	switch w.client.Net {
	case "tcp", "tcp4", "tcp6":
		p = make([]byte, MaxMsgSize)
	case "", "udp", "udp4", "udp6":
		// OPT! TODO(mg)
		p = make([]byte, DefaultMsgSize)
	}
	n, err := w.read(p)
	if err != nil && n == 0 {
		return nil, err
	}
	p = p[:n]
	if err := m.Unpack(p); err != nil {
		return nil, err
	}
	w.rtt = time.Since(w.t)
	m.Size = n
	if t := m.IsTsig(); t != nil {
		secret := t.Hdr.Name
		if _, ok := w.client.TsigSecret[secret]; !ok {
			w.tsigStatus = ErrSecret
			return m, ErrSecret
		}
		// Need to work on the original message p, as that was used to calculate the tsig.
		w.tsigStatus = TsigVerify(p, w.client.TsigSecret[secret], w.tsigRequestMAC, w.tsigTimersOnly)
	}
	return m, w.tsigStatus
}

func (w *reply) read(p []byte) (n int, err error) {
	if w.conn == nil {
		return 0, ErrConnEmpty
	}
	if len(p) < 2 {
		return 0, io.ErrShortBuffer
	}
	attempts := w.client.Attempts
	if attempts == 0 {
		attempts = 1
	}
	switch w.client.Net {
	case "tcp", "tcp4", "tcp6":
		setTimeouts(w)
		for a := 0; a < attempts; a++ {
			n, err = w.conn.(*net.TCPConn).Read(p[0:2])
			if err != nil || n != 2 {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return n, err
			}
			l, _ := unpackUint16(p[0:2], 0)
			if l == 0 {
				return 0, ErrShortRead
			}
			if int(l) > len(p) {
				return int(l), io.ErrShortBuffer
			}
			n, err = w.conn.(*net.TCPConn).Read(p[:l])
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return n, err
			}
			i := n
			for i < int(l) {
				j, err := w.conn.(*net.TCPConn).Read(p[i:int(l)])
				if err != nil {
					if e, ok := err.(net.Error); ok && e.Timeout() {
						// We are half way in our read...
						continue
					}
					return i, err
				}
				i += j
			}
			n = i
		}
	case "", "udp", "udp4", "udp6":
		for a := 0; a < attempts; a++ {
			setTimeouts(w)
			n, _, err = w.conn.(*net.UDPConn).ReadFromUDP(p)
			if err == nil {
				return n, err
			}
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return n, err
			}
		}
	}
	return
}

// send sends a dns msg to the address specified in w.
// If the message m contains a TSIG record the transaction
// signature is calculated.
func (w *reply) send(m *Msg) (err error) {
	var out []byte
	if t := m.IsTsig(); t != nil {
		mac := ""
		name := t.Hdr.Name
		if _, ok := w.client.TsigSecret[name]; !ok {
			return ErrSecret
		}
		out, mac, err = TsigGenerate(m, w.client.TsigSecret[name], w.tsigRequestMAC, w.tsigTimersOnly)
		w.tsigRequestMAC = mac
	} else {
		out, err = m.Pack()
	}
	if err != nil {
		return err
	}
	w.t = time.Now()
	if _, err = w.write(out); err != nil {
		return err
	}
	return nil
}

func (w *reply) write(p []byte) (n int, err error) {
	attempts := w.client.Attempts
	if attempts == 0 {
		attempts = 1
	}
	switch w.client.Net {
	case "tcp", "tcp4", "tcp6":
		if len(p) < 2 {
			return 0, io.ErrShortBuffer
		}
		for a := 0; a < attempts; a++ {
			setTimeouts(w)
			a, b := packUint16(uint16(len(p)))
			n, err = w.conn.Write([]byte{a, b})
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return n, err
			}
			if n != 2 {
				return n, io.ErrShortWrite
			}
			n, err = w.conn.Write(p)
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return n, err
			}
			i := n
			if i < len(p) {
				j, err := w.conn.Write(p[i:len(p)])
				if err != nil {
					if e, ok := err.(net.Error); ok && e.Timeout() {
						// We are half way in our write...
						continue
					}
					return i, err
				}
				i += j
			}
			n = i
		}
	case "", "udp", "udp4", "udp6":
		for a := 0; a < attempts; a++ {
			setTimeouts(w)
			n, err = w.conn.(*net.UDPConn).Write(p)
			if err == nil {
				return
			}
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return n, err
			}
		}
	}
	return
}

func setTimeouts(w *reply) {
	if w.client.ReadTimeout == 0 {
		w.conn.SetReadDeadline(time.Now().Add(2 * 1e9))
	} else {
		w.conn.SetReadDeadline(time.Now().Add(w.client.ReadTimeout))
	}

	if w.client.WriteTimeout == 0 {
		w.conn.SetWriteDeadline(time.Now().Add(2 * 1e9))
	} else {
		w.conn.SetWriteDeadline(time.Now().Add(w.client.WriteTimeout))
	}
}
