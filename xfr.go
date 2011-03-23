package dns

import (
	"os"
)

// Outgoing AXFR and IXFR implementations
// error handling??

// Xfr is used in communicating with *xfr functions.
// This structure is returned on the channel.
type Xfr struct {
	Add bool // true is to be added, otherwise false
	RR
	Err os.Error
}

// Msg tells use what to do
func (d *Conn) XfrRead(q *Msg, m chan Xfr) {
        // Send q first.
        err := d.WriteMsg(q)
        if err != nil {
                return
        }
	switch q.Question[0].Qtype {
	case TypeAXFR:
		d.axfrRead(q, m)
	case TypeIXFR:
		d.ixfrRead(q, m)
	}
}

func (d *Conn) XfrWrite(q *Msg, m chan Xfr) {
	switch q.Question[0].Qtype {
	case TypeAXFR:
		d.axfrWrite(q, m)
	case TypeIXFR:
		//                d.ixfrWrite(q, m)
	}
}

func (d *Conn) axfrRead(q *Msg, m chan Xfr) {
	defer close(m)
	first := true
	in := new(Msg)
	for {
		inb := d.NewBuffer()
		n, err := d.Read(inb)
		if err != nil {
			m <- Xfr{true, nil, err}
			return
		}
		inb = inb[:n]

		if !in.Unpack(inb) {
			m <- Xfr{true, nil, &Error{Error: "Failed to unpack"}}
			return
		}
		if in.Id != q.Id {
			m <- Xfr{true, nil, &Error{Error: "Id mismatch"}}
			return
		}

		if first {
			if !checkXfrSOA(in, true) {
				m <- Xfr{true, nil, &Error{Error: "SOA not first record"}}
				return
			}
			first = !first
		}

		if !first {
			if d.Tsig != nil {
				d.Tsig.TimersOnly = true // Subsequent envelopes use this
			}
			if !checkXfrSOA(in, false) {
				// Soa record not the last one
				sendMsg(in, m, false)
				continue
			} else {
				sendMsg(in, m, true)
				return
			}
		}
	}
	panic("not reached")
	return
}

// Just send the zone
func (d *Conn) axfrWrite(q *Msg, m chan Xfr) {
	out := new(Msg)
	out.Id = q.Id
	out.Question = q.Question
	out.Answer = make([]RR, 1001)
        out.MsgHdr.Response = true
        out.MsgHdr.Authoritative = true
	var soa *RR_SOA
	i := 0
	for r := range m {
		out.Answer[i] = r.RR
		if soa == nil {
			if r.RR.Header().Rrtype != TypeSOA {
				/* ... */
			} else {
				soa = r.RR.(*RR_SOA)
			}
		}
		i++
		if i > 1000 {
			// Send it
			err := d.WriteMsg(out)
			if err != nil {
				/* ... */
			}
			i = 0
                        // Gaat dit goed?
			out.Answer = out.Answer[:0]
		}
		// TimersOnly foo for TSIG
	}
	// Everything is sent, only the closing soa is left.
	out.Answer[i] = soa
        out.Answer = out.Answer[:i+1]
	err := d.WriteMsg(out)
	if err != nil {
		println(err.String())
	}
}

func (d *Conn) ixfrRead(q *Msg, m chan Xfr) {
	defer close(m)
	var serial uint32 // The first serial seen is the current server serial
	var x Xfr
	first := true
	in := new(Msg)
	for {
                inb := d.NewBuffer()
		n, err := d.Read(inb)
		if err != nil {
			m <- Xfr{true, nil, err}
			return
		}
		inb = inb[:n]

		if !in.Unpack(inb) {
			m <- Xfr{true, nil, &Error{Error: "Failed to unpack"}}
			return
		}
		if in.Id != q.Id {
			m <- Xfr{true, nil, &Error{Error: "Id mismatch"}}
			return
		}

		if first {
			// A single SOA RR signals "no changes"
			if len(in.Answer) == 1 && checkXfrSOA(in, true) {
				return
			}

			// But still check if the returned answer is ok
			if !checkXfrSOA(in, true) {
				m <- Xfr{true, nil, &Error{Error: "SOA not first record"}}
				return
			}
			// This serial is important
			serial = in.Answer[0].(*RR_SOA).Serial
			first = !first
		}

		// Now we need to check each message for SOA records, to see what we need to do
		x.Add = true
		if !first {
			if d.Tsig != nil {
				d.Tsig.TimersOnly = true
			}
			for k, r := range in.Answer {
				// If the last record in the IXFR contains the servers' SOA,  we should quit
				if r.Header().Rrtype == TypeSOA {
					switch {
					case r.(*RR_SOA).Serial == serial:
						if k == len(in.Answer)-1 {
							// last rr is SOA with correct serial
							//m <- r dont' send it
							return
						}
						x.Add = true
						if k != 0 {
							// Intermediate SOA
							continue
						}
					case r.(*RR_SOA).Serial != serial:
						x.Add = false
						continue // Don't need to see this SOA
					}
				}
				x.RR = r
				m <- x
			}
		}
	}
	panic("not reached")
	return
}

// Check if he SOA record exists in the Answer section of 
// the packet. If first is true the first RR must be a soa
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

// Send the answer section to the channel
func sendMsg(in *Msg, c chan Xfr, nosoa bool) {
	x := Xfr{Add: true}
	for k, r := range in.Answer {
		if nosoa && k == len(in.Answer)-1 {
			continue
		}
		x.RR = r
		c <- x
	}
}
