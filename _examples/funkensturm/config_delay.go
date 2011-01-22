package main

// This proxy delays pkt that have the RD bit set.
// NSECDELAY is now 1 * 1e9, which means 1 pkt/sec
import (
	"dns"
	"time"
	"dns/resolver"
)

const NSECDELAY = 1 * 1e9 // 1 second, meaning 1 qps
var previous int64        // previous tick

func checkDelay() (ti int64, limitok bool) {
	current := time.Nanoseconds()
	tdiff := (current - previous)
	if tdiff < NSECDELAY {
		// too often
		return previous, false
	}
	return current, true
}

func match(m *dns.Msg, d int) (*dns.Msg, bool) {
	// Matching criteria
	var ok bool
	switch d {
	case IN:
		// only delay pkts with RD bit 
		ok = m.MsgHdr.RecursionDesired == true
	case OUT:
		// nothing
	}

	// Packet Mangling functions
	switch d {
	case IN:
		// nothing
	case OUT:
		// nothing
	}
	return m, ok
}

func delay(m *dns.Msg, ok bool) *dns.Msg {
	var ok1 bool
	switch ok {
	case true:
		previous, ok1 = checkDelay()
		if !ok1 {
			println("Dropping: too often")
			time.Sleep(NSECDELAY)
			return nil
		} else {
			println("Ok: continue")
			qr <- resolver.Msg{m, nil, nil}
			in := <-qr
			return in.Dns
		}
	case false:
		qr <- resolver.Msg{m, nil, nil}
		in := <-qr
		return in.Dns
	}
	return nil
}

// Return the configration
func funkensturm() *Funkensturm {
	f := new(Funkensturm)

	f.Setup = func() bool { previous = time.Nanoseconds(); return true }

	f.Matches = make([]Match, 1)
	f.Matches[0].Op = AND
	f.Matches[0].Func = match

	f.Actions = make([]Action, 1)
	f.Actions[0].Func = delay
	return f
}
