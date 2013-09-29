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

// A Conn represents a connection (which may be short lived) to a DNS server.
type Conn struct {
	net.Conn
	rtt        time.Duration
	t          time.Time
	requestMAC string
}

// A Client defines parameters for a DNS client. A nil Client is usable for sending queries.
type Client struct {
	Net            string            // if "tcp" a TCP query will be initiated, otherwise an UDP one (default is "" for UDP)
	ReadTimeout    time.Duration     // the net.Conn.SetReadTimeout value for new connections (ns), defaults to 2 * 1e9
	WriteTimeout   time.Duration     // the net.Conn.SetWriteTimeout value for new connections (ns), defaults to 2 * 1e9
	TsigSecret     map[string]string // secret(s) for Tsig map[<zonename>]<base64 secret>, zonename must be fully qualified
	SingleInflight bool              // if true suppress multiple outstanding queries for the same Qname, Qtype and Qclass
	group          singleflight
}

// Exchange performs a synchronous UDP query. It sends the message m to the address
// contained in a and waits for an reply.
func Exchange(m *Msg, a string) (r *Msg, err error) {
	co := new(Conn)
	co.Conn, err = net.DialTimeout("udp", a, 5*1e9)
	if err != nil {
		return nil, err
	}
	defer co.Close()
	if err = co.WriteMsg(m, nil); err != nil {
		return nil, err
	}
	r, err = co.ReadMsg(nil)
	return r, err
}

// Exchange performs an synchronous query. It sends the message m to the address
// contained in a and waits for an reply. Basic use pattern with a *dns.Client:
//
//	c := new(dns.Client)
//	in, rtt, err := c.Exchange(message, "127.0.0.1:53")
//
func (c *Client) Exchange(m *Msg, a string) (r *Msg, rtt time.Duration, err error) {
	if !c.SingleInflight {
		return c.exchange(m, a)
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
		return c.exchange(m, a)
	})
	if err != nil {
		return r, rtt, err
	}
	if shared {
		r1 := r.copy()
		r = r1
	}
	return r, rtt, nil
}

func (c *Client) exchange(m *Msg, a string) (r *Msg, rtt time.Duration, err error) {
	co := new(Conn)
	if c.Net == "" {
		co.Conn, err = net.DialTimeout("udp", a, 5*1e9)
	} else {
		co.Conn, err = net.DialTimeout(c.Net, a, 5*1e9)
	}
	if err != nil {
		return nil, 0, err
	}
	defer co.Close()
	if err = co.WriteMsg(m, c.TsigSecret); err != nil {
		return nil, 0, err
	}
	r, err = co.ReadMsg(c.TsigSecret)
	return r, co.rtt, err
}

// Add bufsize
func (co *Conn) ReadMsg(tsigSecret map[string]string) (*Msg, error) {
	var p []byte
	m := new(Msg)
	if _, ok := co.Conn.(*net.TCPConn); ok {
		p = make([]byte, MaxMsgSize)
	} else {
		// OPT! TODO(miek): needs function change
		p = make([]byte, DefaultMsgSize)
	}
	n, err := co.Read(p)
	if err != nil && n == 0 {
		return nil, err
	}
	p = p[:n]
	if err := m.Unpack(p); err != nil {
		return nil, err
	}
	co.rtt = time.Since(co.t)
	if t := m.IsTsig(); t != nil {
		if _, ok := tsigSecret[t.Hdr.Name]; !ok {
			return m, ErrSecret
		}
		// Need to work on the original message p, as that was used to calculate the tsig.
		err = TsigVerify(p, tsigSecret[t.Hdr.Name], co.requestMAC, false)
	}
	return m, err
}

func (co *Conn) Read(p []byte) (n int, err error) {
	if co.Conn == nil {
		return 0, ErrConnEmpty
	}
	if len(p) < 2 {
		return 0, io.ErrShortBuffer
	}
	if t, ok := co.Conn.(*net.TCPConn); ok {
		n, err = t.Read(p[0:2])
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
		n, err = t.Read(p[:l])
		if err != nil {
			return n, err
		}
		i := n
		for i < int(l) {
			j, err := t.Read(p[i:int(l)])
			if err != nil {
				return i, err
			}
			i += j
		}
		n = i
		return n, err
	}
	// assume udp connection
	n, _, err = co.Conn.(*net.UDPConn).ReadFromUDP(p)
	if err != nil {
		return n, err
	}
	return n, err
}

// send sends a dns msg to the address specified in w.
// If the message m contains a TSIG record the transaction
// signature is calculated.
func (co *Conn) WriteMsg(m *Msg, tsigSecret map[string]string) (err error) {
	var out []byte
	if t := m.IsTsig(); t != nil {
		mac := ""
		if _, ok := tsigSecret[t.Hdr.Name]; !ok {
			return ErrSecret
		}
		out, mac, err = TsigGenerate(m, tsigSecret[t.Hdr.Name], co.requestMAC, false)
		// Set for the next read
		co.requestMAC = mac
	} else {
		out, err = m.Pack()
	}
	if err != nil {
		return err
	}
	co.t = time.Now()
	if _, err = co.Write(out); err != nil {
		return err
	}
	return nil
}

func (co *Conn) Write(p []byte) (n int, err error) {
	if t, ok := co.Conn.(*net.TCPConn); ok {
		if len(p) < 2 {
			return 0, io.ErrShortBuffer
		}
		l := make([]byte, 2)
		l[0], l[1] = packUint16(uint16(len(p)))
		p = append(l, p...)
		n, err := t.Write(p)
		if err != nil {
			return n, err
		}
		i := n
		if i < len(p) {
			j, err := t.Write(p[i:len(p)])
			if err != nil {
				return i, err
			}
			i += j
		}
		n = i
		return n, err
	}
	n, err = co.Conn.(*net.UDPConn).Write(p)
	return n, err
}

/*
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
*/
