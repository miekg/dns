package dns

import (
	"testing"
        "time"
)

func TestClientSync(t *testing.T) {
	m := new(Msg)
	m.SetQuestion("miek.nl", TypeSOA)

	c := NewClient()
	r := c.Exchange(m, "85.223.71.124:53")

	if r != nil && r.Rcode != RcodeSuccess {
		t.Log("Failed to get an valid answer")
		t.Fail()
		t.Logf("%v\n", r)
	}
}


func helloMiek(w RequestWriter, r *Msg) {
	w.Send(r)
	reply, _ := w.Receive()
	w.Write(reply)
}

func TestClientASync(t *testing.T) {
	HandleQueryFunc("miek.nl", helloMiek) // All queries for miek.nl will be handled by HelloMiek
	ListenAndQuery(nil, nil)              // Detect if this isn't running

	m := new(Msg)
	m.SetQuestion("miek.nl", TypeSOA)

	c := NewClient()
	c.Do(m, "85.223.71.124:53")

forever:
	for {
		select {
		case n := <-DefaultReplyChan:
			if n[1] != nil && n[1].Rcode != RcodeSuccess {
				t.Log("Failed to get an valid answer")
				t.Fail()
				t.Logf("%v\n", n[1])
			}
			break forever
		}
	}
}

// TestClientEDNS
/*
func TestResolverEdns(t *testing.T) {


	// Add EDNS rr
	edns := new(RR_OPT)
	edns.Hdr.Name = "." // must . be for edns
	edns.Hdr.Rrtype = TypeOPT
	// You can handle an OTP RR as any other, but there
	// are some convience functions
	edns.SetUDPSize(2048)
	edns.SetDo()
	edns.Option = make([]Option, 1)
	edns.SetNsid("") // Empty to request it

	// ask something
	m.Question[0] = Question{"powerdns.nl", TypeDNSKEY, ClassINET}
	m.Extra = make([]RR, 1)
	m.Extra[0] = edns

	in, _ := res.Query(m)
	if in != nil {
		if in.Rcode != RcodeSuccess {
			t.Logf("%v\n", in)
			t.Log("Failed to get an valid answer")
			t.Fail()
		}
	}
}
*/

func TestClientTsigAXFR(t *testing.T) {
	m := new(Msg)
	m.SetAxfr("miek.nl")

        m.SetTsig("axfr", HmacMD5, 300, uint64(time.Seconds()))
        secrets := make(map[string]string)
        secrets["axfr"] = "so6ZGir4GPAqINNh9U5c3A=="

        c := NewClient()
        c.Net = "tcp"
        c.TsigSecret = secrets

        c.XfrReceive(m, "85.223.71.124:53")
        /*
        if err != nil {
                t.Log("%s\n", err.String())
                t.Fail()
        }
        */
}
