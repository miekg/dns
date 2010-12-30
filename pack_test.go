package dns

import (
	"testing"
	"net"
)

func TestPackUnpack(t *testing.T) {
	out := new(Msg)
	r := new(RR_AAAA)
	r.AAAA = net.ParseIP("2001:7b8:206:1:200:39ff:fe59:b187").To16()
	r.Hdr = RR_Header{Name: "a.miek.nl", Rrtype: TypeAAAA, Class: ClassINET, Ttl: 3600}
	out.Answer = make([]RR, 1)
	out.Answer[0] = r

	msg, ok := out.Pack()
	if !ok {
		t.Log("Failed to pack msg with AAAA")
		t.Fail()
	}

	in := new(Msg)
	if !in.Unpack(msg) {
		t.Log("Failed to unpack msg with AAAA")
		t.Fail()
	}

	edns := new(RR_OPT)
	edns.Hdr.Name = "."
	edns.Hdr.Rrtype = TypeOPT
	edns.Hdr.Class = ClassINET
	edns.Hdr.Ttl = 3600
	edns.Option = make([]Option, 1)
	edns.Option[0].Code = OptionCodeNSID
	edns.Option[0].Data = "lalalala"

	_, ok = packRR(edns, msg, 0)
	if !ok {
		t.Logf("%v\n", edns)
		t.Log("Failed")
		t.Fail()
	}

	unpacked, _, ok := unpackRR(msg, 0)
	if !ok {
		t.Logf("%v\n", unpacked)
		t.Log("Failed")
		t.Fail()
	}
}
