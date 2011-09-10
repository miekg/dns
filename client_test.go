package dns

import (
	"testing"
	"time"
)

func TestClientSync(t *testing.T) {
	m := new(Msg)
	m.SetQuestion("miek.nl", TypeSOA)

	c := NewClient()
	r, _ := c.Exchange(m, "85.223.71.124:53")

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
		case n := <-c.ReplyChan:
			if n.Reply != nil && n.Reply.Rcode != RcodeSuccess {
				t.Log("Failed to get an valid answer")
				t.Fail()
				t.Logf("%v\n", n.Reply)
			}
			break forever
		}
	}
}

func TestClientEDNS0(t *testing.T) {
	m := new(Msg)
	m.SetQuestion("miek.nl", TypeDNSKEY)

	edns := new(RR_OPT)
	edns.Hdr.Name = "." // must . be for edns
	edns.Hdr.Rrtype = TypeOPT
	// You can handle an OTP RR as any other, but there
	// are some convience functions
	edns.SetUDPSize(2048)
	edns.SetDo()
	edns.Option = make([]Option, 1)
	edns.SetNsid("") // Empty to request it

	m.Extra = make([]RR, 1)
	m.Extra[0] = edns

	c := NewClient()
	r, _ := c.Exchange(m, "85.223.71.124:53")

	if r != nil && r.Rcode != RcodeSuccess {
		t.Log("Failed to get an valid answer")
		t.Fail()
		t.Logf("%v\n", r)
	}
}

func TestClientTsigAXFR(t *testing.T) {
	m := new(Msg)
	m.SetAxfr("miek.nl")

	m.SetTsig("axfr", HmacMD5, 300, uint64(time.Seconds()))
        TsigGenerate(m, "so6ZGir4GPAqINNh9U5c3A==", "", false)
	secrets := make(map[string]string)
	secrets["axfr"] = "so6ZGir4GPAqINNh9U5c3A=="

        println(m.String())
	c := NewClient()
	c.Net = "tcp"
	c.TsigSecret = secrets

	if err := c.XfrReceive(m, "85.223.71.124:53"); err != nil {
		t.Log("Failed to setup axfr" + err.String())
		t.Fail()
	}
	for {
		ex := <-c.ReplyChan
                println(ex.Reply.String())
                println(ex.Error.String())
                if ex.Error != nil {
                        break
                }
	}
	/*
	   for {
	           // select on c.ReplyChannel
	           // and receive the *Exchange messages
	   }
	*/
}
