package dns

import (
	"net"
	"time"
)

// XfrMsg is used when doing [IA]xfr with a remote server.
type XfrMsg struct {
	Request    *Msg          // the question sent  
	Reply      *Msg          // the answer to the question that was sent   
	Rtt        time.Duration // round trip time  
	RemoteAddr net.Addr      // address of the server 
	Error      error         // if something went wrong, this contains the error  
}

// XfrReceive performs a [AI]xfr request (depends on the message's Qtype). It returns
// a channel of XfrMsg on which the replies from the server are sent. At the end of
// the transfer the channel is closed.
// It panics if the Qtype does not equal TypeAXFR or TypeIXFR. The messages are TSIG checked if
// needed, no other post-processing is performed. The caller must dissect the returned
// messages.
//
// Basic use pattern for receiving an AXFR:
//
//	// m contains the [AI]xfr request
//	t, e := client.XfrReceive(m, "127.0.0.1:53")
//	for r := range t {
//		// ... deal with r.Reply or r.Error
//	}
func (c *Client) XfrReceive(q *Msg, a string) (chan *XfrMsg, error) {
	w := new(reply)
	w.client = c
	w.addr = a
	w.req = q
	if err := w.dial(); err != nil {
		return nil, err
	}
	if err := w.send(q); err != nil {
		return nil, err
	}
	e := make(chan *XfrMsg)
	switch q.Question[0].Qtype {
	case TypeAXFR:
		go w.axfrReceive(e)
		return e, nil
	case TypeIXFR:
		go w.ixfrReceive(e)
		return e, nil
	default:
		return nil, ErrXfrType
	}
	panic("not reached")
}

func (w *reply) axfrReceive(c chan *XfrMsg) {
	first := true
	defer w.conn.Close()
	defer close(c)
	for {
		in, err := w.receive()
		if err != nil {
			c <- &XfrMsg{Request: w.req, Reply: in, Rtt: w.rtt, RemoteAddr: w.conn.RemoteAddr(), Error: err}
			return
		}
		if w.req.Id != in.Id {
			c <- &XfrMsg{Request: w.req, Reply: in, Rtt: w.rtt, RemoteAddr: w.conn.RemoteAddr(), Error: ErrId}
			return
		}
		if first {
			if !checkXfrSOA(in, true) {
				c <- &XfrMsg{Request: w.req, Reply: in, Rtt: w.rtt, RemoteAddr: w.conn.RemoteAddr(), Error: ErrXfrSoa}
				return
			}
			first = !first
		}

		if !first {
			w.tsigTimersOnly = true // Subsequent envelopes use this.
			if checkXfrSOA(in, false) {
				c <- &XfrMsg{Request: w.req, Reply: in, Rtt: w.rtt, RemoteAddr: w.conn.RemoteAddr(), Error: nil}
				return
			}
			c <- &XfrMsg{Request: w.req, Reply: in, Rtt: w.rtt, RemoteAddr: w.conn.RemoteAddr(), Error: nil}
		}
	}
	panic("not reached")
}

func (w *reply) ixfrReceive(c chan *XfrMsg) {
	var serial uint32 // The first serial seen is the current server serial
	first := true
	defer w.conn.Close()
	defer close(c)
	for {
		in, err := w.receive()
		if err != nil {
			c <- &XfrMsg{Request: w.req, Reply: in, Rtt: w.rtt, RemoteAddr: w.conn.RemoteAddr(), Error: err}
			return
		}
		if w.req.Id != in.Id {
			c <- &XfrMsg{Request: w.req, Reply: in, Rtt: w.rtt, RemoteAddr: w.conn.RemoteAddr(), Error: ErrId}
			return
		}
		if first {
			// A single SOA RR signals "no changes"
			if len(in.Answer) == 1 && checkXfrSOA(in, true) {
				c <- &XfrMsg{Request: w.req, Reply: in, Rtt: w.rtt, RemoteAddr: w.conn.RemoteAddr(), Error: nil}
				return
			}

			// Check if the returned answer is ok
			if !checkXfrSOA(in, true) {
				c <- &XfrMsg{Request: w.req, Reply: in, Rtt: w.rtt, RemoteAddr: w.conn.RemoteAddr(), Error: ErrXfrSoa}
				return
			}
			// This serial is important
			serial = in.Answer[0].(*RR_SOA).Serial
			first = !first
		}

		// Now we need to check each message for SOA records, to see what we need to do
		if !first {
			w.tsigTimersOnly = true
			// If the last record in the IXFR contains the servers' SOA,  we should quit
			if v, ok := in.Answer[len(in.Answer)-1].(*RR_SOA); ok {
				if v.Serial == serial {
					c <- &XfrMsg{Request: w.req, Reply: in, Rtt: w.rtt, RemoteAddr: w.conn.RemoteAddr(), Error: nil}
					return
				}
			}
			c <- &XfrMsg{Request: w.req, Reply: in, Rtt: w.rtt, RemoteAddr: w.conn.RemoteAddr()}
		}
	}
	panic("not reached")
}

// XfrSend performs an outgoing Ixfr or Axfr. The function is [AI]xfr agnostic, it is
// up to the caller to correctly send the sequence of messages.
func XfrSend(w ResponseWriter, q *Msg, a string) error {
	switch q.Question[0].Qtype {
	case TypeAXFR, TypeIXFR:
		//		go d.xfrWrite(q, m, e)
	default:
		return ErrXfrType
	}
	return nil
}

/*
// Just send the zone
func (d *Conn) axfrSend(q *Msg, m chan *Xfr, e chan os.Error) {
	out := new(Msg)
	out.Id = q.Id
	out.Question = q.Question
	out.Answer = make([]RR, 1001) // TODO(mg) look at this number
	out.MsgHdr.Response = true
	out.MsgHdr.Authoritative = true
        first := true
	var soa *RR_SOA
	i := 0
	for r := range m {
		out.Answer[i] = r.RR
		if soa == nil {
			if r.RR.Header().Rrtype != TypeSOA {
				e <- ErrXfrSoa
                                return
			} else {
				soa = r.RR.(*RR_SOA)
			}
		}
		i++
		if i > 1000 {
			// Send it
			err := d.WriteMsg(out)
			if err != nil {
				e <- err
                                return
			}
			i = 0
			// Gaat dit goed?
			out.Answer = out.Answer[:0]
                        if first {
                                if d.Tsig != nil {
                                        d.Tsig.TimersOnly = true
                                }
                                first = !first
                        }
		}
	}
	// Everything is sent, only the closing soa is left.
	out.Answer[i] = soa
	out.Answer = out.Answer[:i+1]
	err := d.WriteMsg(out)
	if err != nil {
		e <- err
	}
}
*/

// Check if he SOA record exists in the Answer section of 
// the packet. If first is true the first RR must be a SOA
// if false, the last one should be a SOA
func checkXfrSOA(in *Msg, first bool) bool {
	if len(in.Answer) > 0 {
		if first {
			return in.Answer[0].Header().Rrtype == TypeSOA
		} else {
			return in.Answer[len(in.Answer)-1].Header().Rrtype == TypeSOA
		}
	}
	return false
}
