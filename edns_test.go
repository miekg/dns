package dns

import "testing"

func TestOPTTtl(t *testing.T) {
	e := &OPT{}
	e.Hdr.Name = "."
	e.Hdr.Rrtype = TypeOPT

	if e.Do() {
		t.Fail()
	}

	e.SetDo()
	if !e.Do() {
		t.Fail()
	}

	oldTtl := e.Hdr.Ttl

	if e.Version() != 0 {
		t.Fail()
	}

	e.SetVersion(42)
	if e.Version() != 42 {
		t.Fail()
	}

	e.SetVersion(0)
	if e.Hdr.Ttl != oldTtl {
		t.Fail()
	}

	if e.ExtRcode() != 0 {
		t.Fail()
	}

	e.SetExtRcode(42)
	if e.ExtRcode() != 42 {
		t.Fail()
	}

	e.SetExtRcode(0)
	if e.Hdr.Ttl != oldTtl {
		t.Fail()
	}
}
