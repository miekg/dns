package dns

import (
	"testing"
	"time"
)

func TestClientSync(t *testing.T) {
	HandleFunc("miek.nl.", HelloServer)
	defer HandleRemove("miek.nl.")

	s, addrstr, err := RunLocalUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

	c := new(Client)
	r, _, err := c.Exchange(m, addrstr)
	if err != nil {
		t.Errorf("failed to exchange: %v", err)
	}
	if r != nil && r.Rcode != RcodeSuccess {
		t.Errorf("failed to get an valid answer\n%v", r)
	}
	// And now with plain Exchange().
	r, err = Exchange(m, addrstr)
	if err != nil {
		t.Errorf("failed to exchange: %v", err)
	}
	if r != nil && r.Rcode != RcodeSuccess {
		t.Errorf("failed to get an valid answer\n%v", r)
	}
}

func TestClientEDNS0(t *testing.T) {
	HandleFunc("miek.nl.", HelloServer)
	defer HandleRemove("miek.nl.")

	s, addrstr, err := RunLocalUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeDNSKEY)

	m.SetEdns0(2048, true)

	c := new(Client)
	r, _, err := c.Exchange(m, addrstr)
	if err != nil {
		t.Errorf("failed to exchange: %v", err)
	}

	if r != nil && r.Rcode != RcodeSuccess {
		t.Errorf("failed to get an valid answer\n%v", r)
	}
}

func TestSingleSingleInflight(t *testing.T) {
	HandleFunc("miek.nl.", HelloServer)
	defer HandleRemove("miek.nl.")

	s, addrstr, err := RunLocalUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeDNSKEY)

	c := new(Client)
	c.SingleInflight = true
	nr := 10
	ch := make(chan time.Duration)
	for i := 0; i < nr; i++ {
		go func() {
			_, rtt, _ := c.Exchange(m, addrstr)
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
					t.Errorf("all rtts should be equal.  got %d want %d", rtt, first)
				}
			}
			i++
			if i == 10 {
				break Loop
			}
		}
	}
}

// ExampleUpdateLeaseTSIG shows how to update a lease signed with TSIG.
func ExampleUpdateLeaseTSIG(t *testing.T) {
	m := new(Msg)
	m.SetUpdate("t.local.ip6.io.")
	rr, _ := NewRR("t.local.ip6.io. 30 A 127.0.0.1")
	rrs := make([]RR, 1)
	rrs[0] = rr
	m.Insert(rrs)

	leaseRr := new(OPT)
	leaseRr.Hdr.Name = "."
	leaseRr.Hdr.Rrtype = TypeOPT
	e := new(EDNS0_UL)
	e.Code = EDNS0UL
	e.Lease = 120
	leaseRr.Option = append(leaseRr.Option, e)
	m.Extra = append(m.Extra, leaseRr)

	c := new(Client)
	m.SetTsig("polvi.", HmacMD5, 300, time.Now().Unix())
	c.TsigSecret = map[string]string{"polvi.": "pRZgBrBvI4NAHZYhxmhs/Q=="}

	_, _, err := c.Exchange(m, "127.0.0.1:53")
	if err != nil {
		t.Error(err)
	}
}
