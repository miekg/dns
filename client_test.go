package dns

import (
	"testing"
	"time"
)

func TestClientSync(t *testing.T) {
	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

	c := new(Client)
	r, _ := c.Exchange(m, "85.223.71.124:53")

	if r != nil && r.Rcode != RcodeSuccess {
		t.Log("Failed to get an valid answer")
		t.Fail()
		t.Logf("%v\n", r)
	}
}

func TestClientASync(t *testing.T) {
	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

	c := new(Client)
	c.Do(m, "85.223.71.124:53", nil, func(m, r *Msg, e error, d interface{}) {
		if r != nil && r.Rcode != RcodeSuccess {
			t.Log("Failed to get an valid answer")
			t.Fail()
			t.Logf("%v\n", r)
		}
	})
}

func TestClientEDNS0(t *testing.T) {
	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeDNSKEY)

	m.SetEdns0(2048, true)
	//edns.Option = make([]Option, 1)
	//edns.SetNsid("") // Empty to request it

	c := new(Client)
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
	m.SetTsig("axfr.", HmacMD5, 300, time.Now().Unix())

	c := new(Client)
	c.TsigSecret = map[string]string{"axfr.": "so6ZGir4GPAqINNh9U5c3A=="}
	c.Net = "tcp"

	if a, err := c.XfrReceive(m, "85.223.71.124:53"); err != nil {
		t.Log("Failed to setup axfr: " + err.Error())
		t.Fail()
		return
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

func TestClientAXFRMultipleMessages(t *testing.T) {
	m := new(Msg)
	m.SetAxfr("dnsex.nl.")

	c := new(Client)
	c.Net = "tcp"

	if a, err := c.XfrReceive(m, "85.223.71.124:53"); err != nil {
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
