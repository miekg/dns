package main

// This is a transparant proxy config. All recevied pkt are just forwarded to the
// nameserver, hardcoded to 127.0.0.1 and then return to the original querier
import (
	"dns"
	"time"
	"dns/resolver"
)

const (
        DELAY = 0.5 * 1e9        // half second
)

var previous int64 // previous tick
// Check the delay
func checkDelay(nsecDelay int64) (ti int64, limitok bool) {
	current := time.Nanoseconds()
	tdiff := (current - previous)
        println("tdiff", tdiff)
        println("nsec", nsecDelay)
	if tdiff < nsecDelay {
		// too often
		return previous, false
	}
	return current, true
}

func match(m *dns.Msg, d int) (*dns.Msg, bool) {
	// Matching criteria
	switch d {
	case IN:
		// nothing
	case OUT:
		// Note that when sending back only the mangling is important
		// the actual return code of these function isn't checked by
		// funkensturm
	}

	// Packet Mangling functions
	switch d {
	case IN:
		// nothing
	case OUT:
		// nothing
	}
	return m, true
}

func delay(m *dns.Msg, ok bool) (*dns.Msg, bool) {
        var ok1 bool
	switch ok {
	case true:
                previous, ok1 = checkDelay(DELAY)
		if !ok1 {
		        println("dropping: too often")
                        time.Sleep(DELAY)
                        return nil, false
		} else {
		        println("Ok: continue")
                        qr <- resolver.Msg{m, nil, nil}
                        in := <-qr
                        return in.Dns, true
		}
	case false:
		qr <- resolver.Msg{m, nil, nil}
		in := <-qr
		return in.Dns, true
	}
	return nil, false
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
