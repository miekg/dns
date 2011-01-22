package main

// This is a transparant proxy config. All recevied pkt are just forwarded to the
// nameserver, hardcoded to 127.0.0.1 and then return to the original querier
import (
	"dns"
	"dns/resolver"
)

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

func send(m *dns.Msg, ok bool) *dns.Msg {
	switch ok {
	case true, false:
		qr <- resolver.Msg{m, nil, nil}
		in := <-qr
		return in.Dns
	}
	return nil
}

// qr is global and started by Funkensturm. If you
// need 2 or more resolvers, you'll need to start
// them yourself. This needs to be a global variable
//var qr1 chan resolver.Msg

// Return the configration
func funkensturm() *Funkensturm {
	f := new(Funkensturm)

	f.Setup = func() bool { return true }

	f.Matches = make([]Match, 1)
	f.Matches[0].Op = AND
	f.Matches[0].Func = match

	f.Actions = make([]Action, 1)
	f.Actions[0].Func = send
	return f
}
