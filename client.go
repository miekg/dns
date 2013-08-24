// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

// A client implementation.

import (
	"io"
	"net"
	"time"
)

// Order of events:
// *client -> *reply -> Exchange() -> dial()/send()->write()/receive()->read()

// Do I want make this an interface thingy?
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
	ReadTimeout  time.Duration     // the net.Conn.SetReadTimeout value for new connections (ns), defaults to 2 * 1e9
	WriteTimeout time.Duration     // the net.Conn.SetWriteTimeout value for new connections (ns), defaults to 2 * 1e9
	TsigSecret   map[string]string // secret(s) for Tsig map[<zonename>]<base64 secret>, zonename must be fully qualified
	Inflight     bool              // if true suppress multiple outstanding queries for the same Qname, Qtype and Qclass
	group        singleflight
}

func (c *Client) exchangeMerge(m *Msg, a string, s net.Conn) (r *Msg, rtt time.Duration, err error) {
	if !c.Inflight {
		if s == nil {
			return c.exchange(m, a)
		}
		return c.exchangeConn(m, s)
	}
	// This adds a bunch of garbage, TODO(miek).
	t := "nop"
	if t1, ok := TypeToString[m.Question[0].Qtype]; ok {
		t = t1
	}
	cl := "nop"
	if cl1, ok := ClassToString[m.Question[0].Qclass]; ok {
		cl = cl1
	}
	r, rtt, err, shared := c.group.Do(m.Question[0].Name+t+cl, func() (*Msg, time.Duration, error) {
		if s == nil {
			return c.exchange(m, a)
		}
		return c.exchangeConn(m, s)
	})
	if err != nil {
		return r, rtt, err
	}
	if shared {
		r1 := r.copy()
		r1.Id = r.Id // Copy Id!
		r = r1
	}
	return r, rtt, nil
}

// Exchange performs an synchronous query. It sends the message m to the address
// contained in a and waits for an reply. Basic use pattern with a *dns.Client:
//
//	c := new(dns.Client)
//	in, rtt, err := c.Exchange(message, "127.0.0.1:53")
//
func (c *Client) Exchange(m *Msg, a string) (r *Msg, rtt time.Duration, err error) {
	return c.exchangeMerge(m, a, nil)
}

func (c *Client) exchange(m *Msg, a string) (r *Msg, rtt time.Duration, err error) {
	w := &reply{client: c, addr: a}
	if err = w.dial(); err != nil {
		return nil, 0, err
	}
	defer w.conn.Close()
	if err = w.send(m); err != nil {
		return nil, 0, err
	}
	r, err = w.receive()
	return r, w.rtt, err
}

// ExchangeConn performs an synchronous query. It sends the message m trough the
// connection s and waits for a reply.
func (c *Client) ExchangeConn(m *Msg, s net.Conn) (r *Msg, rtt time.Duration, err error) {
	return c.exchangeMerge(m, "", s)
}

func (c *Client) exchangeConn(m *Msg, s net.Conn) (r *Msg, rtt time.Duration, err error) {
	w := &reply{client: c, conn: s}
	if err = w.send(m); err != nil {
		return nil, 0, err
	}
	r, err = w.receive()
	return r, w.rtt, err
}

// dial connects to the address addr for the network set in c.Net
func (w *reply) dial() (err error) {
	var conn net.Conn
	if w.client.Net == "" {
		conn, err = net.DialTimeout("udp", w.addr, 5*1e9)
	} else {
		conn, err = net.DialTimeout(w.client.Net, w.addr, 5*1e9)
	}
	if err != nil {
		return err
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
	switch w.client.Net {
	case "tcp", "tcp4", "tcp6":
		setTimeouts(w)
		n, err = w.conn.(*net.TCPConn).Read(p[0:2])
		if err != nil || n != 2 {
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
			return n, err
		}
		i := n
		for i < int(l) {
			j, err := w.conn.(*net.TCPConn).Read(p[i:int(l)])
			if err != nil {
				return i, err
			}
			i += j
		}
		n = i
	case "", "udp", "udp4", "udp6":
		setTimeouts(w)
		n, _, err = w.conn.(*net.UDPConn).ReadFromUDP(p)
		if err != nil {
			return n, err
		}
	}
	return n, err
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
	switch w.client.Net {
	case "tcp", "tcp4", "tcp6":
		if len(p) < 2 {
			return 0, io.ErrShortBuffer
		}
		setTimeouts(w)
		l := make([]byte, 2)
		l[0], l[1] = packUint16(uint16(len(p)))
		p = append(l, p...)
		n, err := w.conn.Write(p)
		if err != nil {
			return n, err
		}
		i := n
		if i < len(p) {
			j, err := w.conn.Write(p[i:len(p)])
			if err != nil {
				return i, err
			}
			i += j
		}
		n = i
	case "", "udp", "udp4", "udp6":
		setTimeouts(w)
		n, err = w.conn.(*net.UDPConn).Write(p)
		if err != nil {
			return n, err
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
