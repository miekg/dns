package dns

import (
	"testing"
	"time"
)

func TestClientSync(t *testing.T) {
	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

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
	HandleQueryFunc("miek.nl.", helloMiek) // All queries for miek.nl will be handled by HelloMiek
	ListenAndQuery(nil, nil)               // Detect if this isn't running

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

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
	m.SetQuestion("miek.nl.", TypeDNSKEY)

	m.SetEdns0(2048, true)
	//edns.Option = make([]Option, 1)
	//edns.SetNsid("") // Empty to request it

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
	m.SetAxfr("miek.nl.")

	m.SetTsig("axfr.", HmacMD5, 300, uint64(time.Now().Unix()))
	TsigGenerate(m, "so6ZGir4GPAqINNh9U5c3A==", "", false)
	secrets := make(map[string]string)
	secrets["axfr."] = "so6ZGir4GPAqINNh9U5c3A=="

	c := NewClient()
	c.Net = "tcp"
	c.TsigSecret = secrets

	if err := c.XfrReceive(m, "85.223.71.124:53"); err != nil {
		t.Log("Failed to setup axfr" + err.Error())
		t.Fail()
		return
	}
	for {
		ex := <-c.ReplyChan
		t.Log(ex.Reply.String())
		if ex.Error == ErrXfrLast {
			break
		}
		if ex.Error != nil {
			t.Logf("Error %s\n", ex.Error.Error())
			t.Fail()
			break
		}
		if ex.Reply.Rcode != RcodeSuccess {
			break
		}
	}
}

func TestClientAXFRMultipleMessages(t *testing.T) {
	m := new(Msg)
	m.SetAxfr("dnsex.nl.")

	c := NewClient()
	c.Net = "tcp"

	if err := c.XfrReceive(m, "85.223.71.124:53"); err != nil {
		t.Log("Failed to setup axfr" + err.Error())
		t.Fail()
		return
	}
	for {
		ex := <-c.ReplyChan
		t.Log(ex.Reply.String())
		if ex.Error == ErrXfrLast {
			break
		}
		if ex.Error != nil {
			t.Logf("Error %s\n", ex.Error.Error())
			t.Fail()
			break
		}
		if ex.Reply.Rcode != RcodeSuccess {
			break
		}
	}
}
