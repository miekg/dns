package main

// This proxy delays pkt that have the RD bit set.

import (
        "os"
	"dns"
        "fmt"
	"time"
)

const NSECDELAY = 1 * 1e9 // 1 second, meaning 1 qps (smaller means higher qps)

var previous int64 // previous tick

// returns false if we hit the limit set by NSECDELAY
func checkDelay() (ti int64, limitok bool) {
	current := time.Nanoseconds()
	tdiff := (current - previous)
	if tdiff < NSECDELAY {
		// too often
		return previous, false
	}
	return current, true
}

// the only matching we do is on the RD bit
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

	// Packet Mangling
	switch d {
	case IN:
		// nothing
	case OUT:
		// nothing
	}
	return m, ok
}

func delay(m *dns.Msg, ok bool) (out *dns.Msg) {
	var ok1 bool
	switch ok {
	case true:
		previous, ok1 = checkDelay()
		if !ok1 {
			fmt.Fprintf(os.Stderr, "Info: Dropping: too often\n")
			time.Sleep(NSECDELAY)
			return
		} else {
			fmt.Fprintf(os.Stderr, "Info: Ok: let it through\n")
                        for _, r := range qr {
			        out, _ = r.Query(m)
                        }
			return
		}
	case false:
                for _, r := range qr {
                        out, _ = r.Query(m)
                }
		return
	}
	return
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
