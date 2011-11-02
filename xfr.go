package dns

// XfrReceives requests an incoming Ixfr or Axfr. If the message q's question
// section contains an AXFR type an Axfr is performed, if it is IXFR it does an Ixfr.
// Each message will be send along the Client's reply channel as it is received. 
// The last message send has Exchange.Error set to ErrXfrLast
// to signal there is nothing more to come.
func (c *Client) XfrReceive(q *Msg, a string) error {
	w := new(reply)
	w.client = c
	w.addr = a
	w.req = q
	if err := w.Dial(); err != nil {
		return err
	}
	if err := w.Send(q); err != nil {
		return err
	}
	switch q.Question[0].Qtype {
	case TypeAXFR:
		go w.axfrReceive()
	case TypeIXFR:
		go w.ixfrReceive()
	default:
		return ErrXfrType
	}
	return nil
}

func (w *reply) axfrReceive() {
	first := true
	defer w.Close()
	for {
		in, err := w.Receive()
		if err != nil {
			w.Client().ReplyChan <- &Exchange{w.req, in, err}
			return
		}
		if w.req.Id != in.Id {
			w.Client().ReplyChan <- &Exchange{w.req, in, ErrId}
			return
		}

		if first {
			if !checkXfrSOA(in, true) {
				w.Client().ReplyChan <- &Exchange{w.req, in, ErrXfrSoa}
				return
			}
			first = !first
		}

		if !first {
			w.tsigTimersOnly = true // Subsequent envelopes use this.
			if checkXfrSOA(in, false) {
				w.Client().ReplyChan <- &Exchange{w.req, in, ErrXfrLast}
				return
			}
			w.Client().ReplyChan <- &Exchange{Request: w.req, Reply: in}
		}
	}
	panic("not reached")
	return
}

func (w *reply) ixfrReceive() {
	var serial uint32 // The first serial seen is the current server serial
	first := true
	defer w.Close()
	for {
		in, err := w.Receive()
		if err != nil {
			w.Client().ReplyChan <- &Exchange{w.req, in, err}
			return
		}
		if w.req.Id != in.Id {
			w.Client().ReplyChan <- &Exchange{w.req, in, ErrId}
			return
		}

		if first {
			// A single SOA RR signals "no changes"
			if len(in.Answer) == 1 && checkXfrSOA(in, true) {
				w.Client().ReplyChan <- &Exchange{w.req, in, ErrXfrLast}
				return
			}

			// Check if the returned answer is ok
			if !checkXfrSOA(in, true) {
				w.Client().ReplyChan <- &Exchange{w.req, in, ErrXfrSoa}
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
					w.Client().ReplyChan <- &Exchange{w.req, in, ErrXfrLast}
					return
				}
			}
			w.Client().ReplyChan <- &Exchange{Request: w.req, Reply: in}
		}
	}
	panic("not reached")
	return
}

// XfrSend performs an outgoing Ixfr or Axfr. The function is xfr agnostic, it is
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
func (d *Conn) axfrWrite(q *Msg, m chan *Xfr, e chan os.Error) {
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
