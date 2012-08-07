package dns

// A concurrent client implementation. 

import (
	"io"
	"net"
	"time"
)

// hijacked connections...?
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

// A nil Client is usable.
type Client struct {
	Net          string            // if "tcp" a TCP query will be initiated, otherwise an UDP one (default is "", is UDP)
	Attempts     int               // number of attempts, if not set defaults to 1
	Retry        bool              // retry with TCP
	ReadTimeout  time.Duration     // the net.Conn.SetReadTimeout value for new connections (ns), defauls to 2 * 1e9
	WriteTimeout time.Duration     // the net.Conn.SetWriteTimeout value for new connections (ns), defauls to 2 * 1e9
	TsigSecret   map[string]string // secret(s) for Tsig map[<zonename>]<base64 secret>
	// Hijacked     net.Conn       // if set the calling code takes care of the connection
	// LocalAddr string            // Local address to use
}

func (w *reply) RemoteAddr() net.Addr {
	if w.conn == nil {
		return nil
	} else {
		return w.conn.RemoteAddr()
	}
	return nil
}

// Do performs an asynchronous query. The msg *Msg is the question to ask, the 
// string addr is the address of the nameserver, the parameter data in
// in the callback function. The call backback function is called with the
// origin query, the answer returned from the nameserver, optional error and
// data.
func (c *Client) Do(msg *Msg, addr string, data interface{}, callback func(*Msg, *Msg, error, interface{})) {
	go func() {
		r, err := c.Exchange(msg, addr)
		callback(msg, r, err, data)
	}()
}

// exchangeBuffer performs a synchronous query. It sends the buffer m to the
// address contained in a.
func (c *Client) exchangeBuffer(inbuf []byte, a string, outbuf []byte) (n int, w *reply, err error) {
	w = new(reply)
	w.client = c
	w.addr = a
	if err = w.dial(); err != nil {
		return 0, w, err
	}
	defer w.Close()
	w.t = time.Now()
	if n, err = w.writeClient(inbuf); err != nil {
		return 0, w, err
	}
	if n, err = w.readClient(outbuf); err != nil {
		return n, w, err
	}
	w.rtt = time.Since(w.t)
	return n, w, nil
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
	var n int
	var w *reply
	out, ok := m.Pack()
	if !ok {
		return nil, 0, ErrPack
	}
	var in []byte
	switch c.Net {
	case "tcp", "tcp4", "tcp6":
		in = make([]byte, MaxMsgSize)
	case "", "udp", "udp4", "udp6":
		size := UDPMsgSize
		for _, r := range m.Extra {
			if r.Header().Rrtype == TypeOPT {
				size = int(r.(*RR_OPT).UDPSize())
			}
		}
		in = make([]byte, size)
	}
	if n, w, err = c.exchangeBuffer(out, a, in); err != nil {
		if w.conn != nil {
			return nil, 0, err
		}
		return nil, 0, err
	}
	r = new(Msg)
	r.Size = n
	if ok := r.Unpack(in[:n]); !ok {
		return nil, w.rtt, ErrUnpack
	}
	return r, w.rtt, nil
}

// dial connects to the address addr for the network set in c.Net
func (w *reply) dial() (err error) {
	var conn net.Conn
	if w.Client().Net == "" {
		conn, err = net.Dial("udp", w.addr)
	} else {
		conn, err = net.Dial(w.Client().Net, w.addr)
	}
	if err != nil {
		return
	}
	w.conn = conn
	return nil
}

func (w *reply) receive() (*Msg, error) {
	var p []byte
	m := new(Msg)
	switch w.Client().Net {
	case "tcp", "tcp4", "tcp6":
		p = make([]byte, MaxMsgSize)
	case "", "udp", "udp4", "udp6":
		p = make([]byte, DefaultMsgSize)
	}
	n, err := w.readClient(p)
	if err != nil || n == 0 {
		return nil, err
	}
	p = p[:n]
	if ok := m.Unpack(p); !ok {
		return nil, ErrUnpack
	}
	w.rtt = time.Since(w.t)
	m.Size = n
	if m.IsTsig() {
		secret := m.Extra[len(m.Extra)-1].(*RR_TSIG).Hdr.Name
		if _, ok := w.Client().TsigSecret[secret]; !ok {
			w.tsigStatus = ErrSecret
			return m, nil
		}
		// Need to work on the original message p, as that was used to calculate the tsig.
		w.tsigStatus = TsigVerify(p, w.Client().TsigSecret[secret], w.tsigRequestMAC, w.tsigTimersOnly)
	}
	return m, nil
}

func (w *reply) readClient(p []byte) (n int, err error) {
	if w.conn == nil {
		return 0, ErrConnEmpty
	}
	if len(p) < 1 {
		return 0, io.ErrShortBuffer
	}
	attempts := w.Client().Attempts
	if attempts == 0 {
		attempts = 1
	}
	switch w.Client().Net {
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
	if m.IsTsig() {
		mac := ""
		name := m.Extra[len(m.Extra)-1].(*RR_TSIG).Hdr.Name
		if _, ok := w.Client().TsigSecret[name]; !ok {
			return ErrSecret
		}
		out, mac, err = TsigGenerate(m, w.Client().TsigSecret[name], w.tsigRequestMAC, w.tsigTimersOnly)
		if err != nil {
			return err
		}
		w.tsigRequestMAC = mac
	} else {
		ok := false
		out, ok = m.Pack()
		if !ok {
			return ErrPack
		}
	}
	w.t = time.Now()
	if _, err = w.writeClient(out); err != nil {
		return err
	}
	return nil
}

func (w *reply) writeClient(p []byte) (n int, err error) {
	attempts := w.Client().Attempts
	if attempts == 0 {
		attempts = 1
	}
	if err = w.dial(); err != nil {
		return 0, err
	}
	switch w.Client().Net {
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
	if w.Client().ReadTimeout == 0 {
		w.conn.SetReadDeadline(time.Now().Add(2 * 1e9))
	} else {
		w.conn.SetReadDeadline(time.Now().Add(w.Client().ReadTimeout))
	}

	if w.Client().WriteTimeout == 0 {
		w.conn.SetWriteDeadline(time.Now().Add(2 * 1e9))
	} else {
		w.conn.SetWriteDeadline(time.Now().Add(w.Client().WriteTimeout))
	}
}

// Close implents the RequestWriter.Close method
func (w *reply) Close() (err error) { return w.conn.Close() }

// Client returns a pointer to the client
func (w *reply) Client() *Client { return w.client }

// Request returns the request contained in reply
func (w *reply) Request() *Msg { return w.req }

// TsigStatus implements the RequestWriter.TsigStatus method
func (w *reply) TsigStatus() error { return w.tsigStatus }
