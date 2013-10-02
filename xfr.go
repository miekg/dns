// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"net"
	"time"
)

// Envelope is used when doing [IA]XFR with a remote server.
type Envelope struct {
	RR    []RR  // The set of RRs in the answer section of the AXFR reply message.
	Error error // If something went wrong, this contains the error.
}

type Transfer struct {
	Conn
	DialTimeout    time.Duration     // net.DialTimeout (ns), defaults to 2 * 1e9
	ReadTimeout    time.Duration     // net.Conn.SetReadTimeout value for connections (ns), defaults to 2 * 1e9
	WriteTimeout   time.Duration     // net.Conn.SetWriteTimeout value for connections (ns), defaults to 2 * 1e9
	TsigSecret     map[string]string // secret(s) for Tsig map[<zonename>]<base64 secret>, zonename must be fully qualified
	tsigTimersOnly bool
}

// In performs a [AI]XFR request (depends on the message's Qtype). It returns
// a channel of *Envelope on which the replies from the server are sent.
// At the end of the transfer the channel is closed.
// The messages are TSIG checked if needed, no other post-processing is performed.
// The caller must dissect the returned messages.
//
// Basic use pattern for receiving an AXFR:
//
//	// m contains the AXFR request
//	t := new(dns.Transfer)
//	c, e := t.In(m, "127.0.0.1:53")
//	for env := range c
//		// ... deal with env.RR or env.Error
//	}

func (t *Transfer) In(q *Msg, a string, env chan *Envelope) (err error) {
	co := new(Conn)
	timeout := dnsTimeout
	if t.DialTimeout != 0 {
		timeout = t.DialTimeout
	}
	co.Conn, err = net.DialTimeout("tcp", a, timeout)
	if err != nil {
		return err
	}
	// re-read 'n stuff must be pushed down
	timeout = dnsTimeout
	if t.ReadTimeout != 0 {
		timeout = t.ReadTimeout
	}
	co.SetReadDeadline(time.Now().Add(dnsTimeout))
	timeout = dnsTimeout
	if t.WriteTimeout != 0 {
		timeout = t.WriteTimeout
	}
	co.SetWriteDeadline(time.Now().Add(dnsTimeout))
	defer co.Close()
	return nil
}

// Out performs an outgoing [AI]XFR depending on the request message. The
// caller is responsible for sending the correct sequence of RR sets through
// the channel c. For reasons of symmetry Envelope is re-used.
// Errors are signaled via the error pointer, when an error occurs the function
// sets the error and returns (it does not close the channel).
// TSIG and enveloping is handled by TransferOut.
//
// Basic use pattern for sending an AXFR:
//
//	// m contains the AXFR request
//	t := new(dns.Transfer)
//	env := make(chan *dns.Envelope)
//	err := t.Out(m, c, e)
//	for rrset := range rrsets {	// rrsets is a []RR
//		c <- &{Envelope{RR: rrset}
//		if e != nil {
//			close(c)
//			break
//		}
//	}
//	// w.Close() // Don't! Let the client close the connection
func (t *Transfer) Out(q *Msg, a string) (chan *Envelope, error) {
	return nil, nil
}

// ReadMsg reads a message from the transfer connection t.
func (t *Transfer) ReadMsg() (*Msg, error) {
	m := new(Msg)
	p := make([]byte, MaxMsgSize)
	n, err := t.Conn.Read(p)
	if err != nil && n == 0 {
		return nil, err
	}
	p = p[:n]
	if err := m.Unpack(p); err != nil {
		return nil, err
	}
	if ts := m.IsTsig(); t != nil {
		if _, ok := t.TsigSecret[ts.Hdr.Name]; !ok {
			return m, ErrSecret
		}
		// Need to work on the original message p, as that was used to calculate the tsig.
		err = TsigVerify(p, t.TsigSecret[ts.Hdr.Name], t.requestMAC, false)
	}
	return m, err
}

// WriteMsg write a message throught the transfer connection t.
func (t *Transfer) WriteMsg(m *Msg) (err error) {
	var out []byte
	if ts := m.IsTsig(); t != nil {
		mac := ""
		if _, ok := t.TsigSecret[ts.Hdr.Name]; !ok {
			return ErrSecret
		}
		out, mac, err = TsigGenerate(m, t.TsigSecret[ts.Hdr.Name], t.requestMAC, false)
		// Set for the next read, allthough only used in zone transfers
		t.requestMAC = mac
	} else {
		out, err = m.Pack()
	}
	if err != nil {
		return err
	}
	if _, err = t.Conn.Write(out); err != nil {
		return err
	}
	return nil
}

/*
func (c *Client) TransferIn(q *Msg, a string) (chan *Envelope, error) {
	e := make(chan *Envelope)
	switch q.Question[0].Qtype {
	case TypeAXFR:
		go w.axfrIn(q, e)
		return e, nil
	case TypeIXFR:
		go w.ixfrIn(q, e)
		return e, nil
	default:
		return nil, nil
	}
	panic("dns: not reached")
}

func (w *reply) axfrIn(q *Msg, c chan *Envelope) {
	first := true
	defer w.conn.Close()
	defer close(c)
	for {
		in, err := w.receive()
		if err != nil {
			c <- &Envelope{nil, err}
			return
		}
		if in.Id != q.Id {
			c <- &Envelope{in.Answer, ErrId}
			return
		}
		if first {
			if !checkSOA(in, true) {
				c <- &Envelope{in.Answer, ErrSoa}
				return
			}
			first = !first
			// only one answer that is SOA, receive more
			if len(in.Answer) == 1 {
				w.tsigTimersOnly = true
				c <- &Envelope{in.Answer, nil}
				continue
			}
		}

		if !first {
			w.tsigTimersOnly = true // Subsequent envelopes use this.
			if checkSOA(in, false) {
				c <- &Envelope{in.Answer, nil}
				return
			}
			c <- &Envelope{in.Answer, nil}
		}
	}
	panic("dns: not reached")
}

func (w *reply) ixfrIn(q *Msg, c chan *Envelope) {
	var serial uint32 // The first serial seen is the current server serial
	first := true
	defer w.conn.Close()
	defer close(c)
	for {
		in, err := w.receive()
		if err != nil {
			c <- &Envelope{in.Answer, err}
			return
		}
		if q.Id != in.Id {
			c <- &Envelope{in.Answer, ErrId}
			return
		}
		if first {
			// A single SOA RR signals "no changes"
			if len(in.Answer) == 1 && checkSOA(in, true) {
				c <- &Envelope{in.Answer, nil}
				return
			}

			// Check if the returned answer is ok
			if !checkSOA(in, true) {
				c <- &Envelope{in.Answer, ErrSoa}
				return
			}
			// This serial is important
			serial = in.Answer[0].(*SOA).Serial
			first = !first
		}

		// Now we need to check each message for SOA records, to see what we need to do
		if !first {
			w.tsigTimersOnly = true
			// If the last record in the IXFR contains the servers' SOA,  we should quit
			if v, ok := in.Answer[len(in.Answer)-1].(*SOA); ok {
				if v.Serial == serial {
					c <- &Envelope{in.Answer, nil}
					return
				}
			}
			c <- &Envelope{in.Answer, nil}
		}
	}
	panic("dns: not reached")
}

// Check if he SOA record exists in the Answer section of
// the packet. If first is true the first RR must be a SOA
// if false, the last one should be a SOA.
func checkSOA(in *Msg, first bool) bool {
	if len(in.Answer) > 0 {
		if first {
			return in.Answer[0].Header().Rrtype == TypeSOA
		} else {
			return in.Answer[len(in.Answer)-1].Header().Rrtype == TypeSOA
		}
	}
	return false
}

func TransferOut(w ResponseWriter, q *Msg, c chan *Envelope, e *error) error {
	switch q.Question[0].Qtype {
	case TypeAXFR, TypeIXFR:
		go xfrOut(w, q, c, e)
		return nil
	default:
		return nil
	}
	panic("dns: not reached")
}

// TODO(mg): count the RRs and the resulting size.
func xfrOut(w ResponseWriter, req *Msg, c chan *Envelope, e *error) {
	rep := new(Msg)
	rep.SetReply(req)
	rep.Authoritative = true

	for x := range c {
		// assume it fits
		rep.Answer = append(rep.Answer, x.RR...)
		if err := w.WriteMsg(rep); e != nil {
			*e = err
			return
		}
		w.TsigTimersOnly(true)
		rep.Answer = nil
	}
}
*/
