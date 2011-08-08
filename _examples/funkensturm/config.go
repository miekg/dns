package main

import (
	"dns"
)

func send(m *dns.Msg) (buf []byte) {
	var o *dns.Msg
	for _, c := range qr {
		o, _ = c.Client.Exchange(m, c.Addr)
	}
	buf, _ = o.Pack()
	return
}

// Return the configration
func NewFunkenSturm() *FunkenSturm {
	f := new(FunkenSturm)
	f.Setup = func() bool { return true } // no setup
	f.Default = send

	f.Funk = make([]*Funk, 1) // 1 Funk chain
	f.Funk[0] = new(Funk)
	f.Funk[0].Match = func(m *dns.Msg) (*dns.Msg, bool) { return m, true }
	f.Funk[0].Action = send
	return f
}
