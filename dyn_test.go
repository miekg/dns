package dns

// Find better solution

/*
import (
	"net"
	"testing"
)

func sendit(u *Msg) (r *Msg, e error) {
	c := new(Client)
	r, e = c.Exchange(u, "127.0.0.1:53")
	return r, e
}
*/

/*
func TestUpdateAdd(t *testing.T) {
	u := new(Msg)
	u.SetUpdate("dyn.atoom.net.")
	a := new(RR_A)
	a.Hdr = RR_Header{"miek2.dyn.atoom.net.", TypeA, ClassINET, 1000, 0}
	a.A = net.IPv4(127, 0, 0, 1)
	rr := make([]RR, 1)
	rr[0] = a
	u.RRsetAddRdata(rr)
	t.Log(u.String())

	r, e := sendit(u)
	if e != nil {
		t.Log("Failed: " + e.Error())
		t.Fail()
	}
	if r != nil && r.Rcode != RcodeSuccess {
		t.Log("Failed: " + r.String())
		t.Fail()
	}
	t.Log(r.String())
}

func TestUpdateDelete(t *testing.T) {
	u := new(Msg)
	u.SetUpdate("dyn.atoom.net.")
	a := new(RR_A)
	a.Hdr = RR_Header{"miek2.dyn.atoom.net.", TypeA, ClassINET, 1000, 0}
	a.A = nil
	rr := make([]RR, 1)
	rr[0] = a
	u.RRsetDelete(rr)
	t.Log(u.String())

	r, e := sendit(u)
	if e != nil {
		t.Log("Failed: " + e.Error())
		t.Fail()
		return
	}
	if r != nil && r.Rcode != RcodeSuccess {
		t.Log("Failed: " + r.String())
		t.Fail()
		return
	}
	t.Log(r.String())
}
*/
