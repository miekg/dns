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

// not really a test, but shows how to use update leases
func TestUpdateLeaseTSIG(t *testing.T) {
	m := new(Msg)
	m.SetUpdate("t.local.ip6.io.")
	rr, _ := NewRR("t.local.ip6.io. 30 A 127.0.0.1")
	rrs := make([]RR, 1)
	rrs[0] = rr
	m.AddRR(rrs)

	lease_rr := new(RR_OPT)
	lease_rr.Hdr.Name = "."
	lease_rr.Hdr.Rrtype = TypeOPT
	e := new(EDNS0_UPDATE_LEASE)
	e.Code = EDNS0UPDATELEASE
	e.Lease = 120
	lease_rr.Option = append(lease_rr.Option, e)
	m.Extra = append(m.Extra, lease_rr)

	c := new(Client)
	m.SetTsig("polvi.", HmacMD5, 300, time.Now().Unix())
	c.TsigSecret = map[string]string{"polvi.": "pRZgBrBvI4NAHZYhxmhs/Q=="}

	w := new(reply)
	w.client = c
	w.addr = "127.0.0.1:53"
	w.req = m

	if err := w.dial(); err != nil {
		t.Fail()
	}
	if err := w.send(m); err != nil {
		t.Fail()
	}

}
