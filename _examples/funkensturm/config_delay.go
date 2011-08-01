package main

// This proxy delays pkt that have the RD bit set.

import (
	"dns"
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
func match(m *dns.Msg) (*dns.Msg, bool) {
	// only delay pkts with RD bit 
	return m, m.MsgHdr.RecursionDesired == true
}

func delay(m *dns.Msg) (buf []byte) {
	var (
		ok1 bool
		o   *dns.Msg
	)
        if previous, ok1 = checkDelay(); !ok1 {
                println("Info: Dropping: too often")
                time.Sleep(NSECDELAY)
                return
        }
        println("Info: Ok: let it through")
        for _, c := range qr {
                o = c.Client.Exchange(m, c.Addr)
        }
        buf, _ = o.Pack()
        return
}

// Return the configration
func NewFunkenSturm() *FunkenSturm {
	f := new(FunkenSturm)
	f.Funk = make([]*Funk, 1)
	// Not concurrent save
	f.Setup = func() bool { previous = time.Nanoseconds(); return true }

	f.Funk[0] = NewFunk(1)
	f.Funk[0].Matches[0].Op = AND
	f.Funk[0].Matches[0].Func = match
	f.Funk[0].Action = delay
	return f
}
