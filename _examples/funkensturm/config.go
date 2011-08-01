package main

import (
	"dns"
)

func match(m *dns.Msg) (*dns.Msg, bool) {
	return m, true
}

func send(m *dns.Msg) (buf []byte) {
	var o *dns.Msg
	for _, c := range qr {
		o = c.Client.Exchange(m, c.Addr)
	}
	buf, _ = o.Pack()
	return
}

// Return the configration
func NewFunkenSturm() *FunkenSturm {
	f := new(FunkenSturm)
	f.Funk = make([]*Funk, 1)             // 1 Chain
	f.Setup = func() bool { return true } // no setup
	f.Funk[0] = NewFunk(1)                // First chains with 1 match/action
	f.Funk[0].Matches[0].Op = AND
	f.Funk[0].Matches[0].Func = func(m *dns.Msg) (*dns.Msg, bool) { return m ,true }
	f.Funk[0].Action = send
	return f
}
