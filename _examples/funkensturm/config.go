package main

// This is transparant proxy

import (
	"dns"
	"fmt"
)

func send(m *dns.Msg) (buf []byte) {
	if *verbose {
		fmt.Printf("--> %s\n", m.Question[0].String())
	}

	var o *dns.Msg
	var err error
	for _, c := range qr {
		o, err = c.Client.Exchange(m, c.Addr)
		if *verbose {
			if err == nil {
				fmt.Printf("<-- %s\n", m.Question[0].String())
			} else {
				fmt.Printf("%s\n", err.Error())
			}
		}
	}
	if err == nil {
		buf, _ = o.Pack()
	}
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
