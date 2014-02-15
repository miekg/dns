// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"testing"
	"time"
)

func newTestServer(t *testing.T) {
	// Defined in server_test.go
	HandleFunc("miek.nl.", HelloServer)
	HandleFunc("example.com.", AnotherHelloServer)
	go func() {
		err := ListenAndServe(":8063", "udp", nil)
		if err != nil {
			t.Log("ListenAndServe: ", err.Error())
			t.Fatal()
		}
	}()
	time.Sleep(4e8)
}

func TestClientSync(t *testing.T) {
	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

	c := new(Client)
	r, _, _ := c.Exchange(m, "127.0.0.1:6053")

	if r != nil && r.Rcode != RcodeSuccess {
		t.Log("Failed to get an valid answer")
		t.Fail()
		t.Logf("%v\n", r)
	}
}

func TestClientEDNS0(t *testing.T) {
	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeDNSKEY)

	m.SetEdns0(2048, true)

	c := new(Client)
	r, _, _ := c.Exchange(m, "127.0.0.1:6053")

	if r != nil && r.Rcode != RcodeSuccess {
		t.Log("Failed to get an valid answer")
		t.Fail()
		t.Logf("%v\n", r)
	}
}

func TestSingleSingleInflight(t *testing.T) {
	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeDNSKEY)

	c := new(Client)
	c.SingleInflight = true
	nr := 10
	ch := make(chan time.Duration)
	for i := 0; i < nr; i++ {
		go func() {
			_, rtt, _ := c.Exchange(m, "127.0.0.1:6053")
			ch <- rtt
		}()
	}
	i := 0
	var first time.Duration
	// With inflight *all* rtt are identical, and by doing actual lookups
	// the changes that this is a coincidence is small.
Loop:
	for {
		select {
		case rtt := <-ch:
			if i == 0 {
				first = rtt
			} else {
				if first != rtt {
					t.Log("All rtt should be equal")
					t.Fail()
				}
			}
			i++
			if i == 10 {
				break Loop
			}
		}
	}
}

/*
func TestClientTsigAXFR(t *testing.T) {
	m := new(Msg)
	m.SetAxfr("example.nl.")
	m.SetTsig("axfr.", HmacMD5, 300, time.Now().Unix())

	tr := new(Transfer)
	tr.TsigSecret = map[string]string{"axfr.": "so6ZGir4GPAqINNh9U5c3A=="}

	if a, err := tr.In(m, "176.58.119.54:53"); err != nil {
		t.Log("Failed to setup axfr: " + err.Error())
		t.Fatal()
	} else {
		for ex := range a {
			if ex.Error != nil {
				t.Logf("Error %s\n", ex.Error.Error())
				t.Fail()
				break
			}
			for _, rr := range ex.RR {
				t.Logf("%s\n", rr.String())
			}
		}
	}
}

func TestClientAXFRMultipleEnvelopes(t *testing.T) {
	m := new(Msg)
	m.SetAxfr("nlnetlabs.nl.")

	tr := new(Transfer)
	if a, err := tr.In(m, "213.154.224.1:53"); err != nil {
		t.Log("Failed to setup axfr" + err.Error())
		t.Fail()
		return
	} else {
		for ex := range a {
			if ex.Error != nil {
				t.Logf("Error %s\n", ex.Error.Error())
				t.Fail()
				break
			}
		}
	}
}
*/

// ExapleUpdateLeaseTSIG shows how to update a lease signed with TSIG.
func ExampleUpdateLeaseTSIG(t *testing.T) {
	m := new(Msg)
	m.SetUpdate("t.local.ip6.io.")
	rr, _ := NewRR("t.local.ip6.io. 30 A 127.0.0.1")
	rrs := make([]RR, 1)
	rrs[0] = rr
	m.Insert(rrs)

	lease_rr := new(OPT)
	lease_rr.Hdr.Name = "."
	lease_rr.Hdr.Rrtype = TypeOPT
	e := new(EDNS0_UL)
	e.Code = EDNS0UL
	e.Lease = 120
	lease_rr.Option = append(lease_rr.Option, e)
	m.Extra = append(m.Extra, lease_rr)

	c := new(Client)
	m.SetTsig("polvi.", HmacMD5, 300, time.Now().Unix())
	c.TsigSecret = map[string]string{"polvi.": "pRZgBrBvI4NAHZYhxmhs/Q=="}

	_, _, err := c.Exchange(m, "127.0.0.1:53")
	if err != nil {
		t.Log(err.Error())
		t.Fail()
	}
}
