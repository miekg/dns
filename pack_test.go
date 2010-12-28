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

	key := new(RR_DNSKEY)
	key.Hdr = RR_Header{Name: "miek.nl.", Rrtype: TypeDNSKEY, Class: ClassINET, Ttl: 3600}
	key = &RR_DNSKEY{Flags: 257, Protocol: 3, Algorithm: AlgRSASHA1}
	key.PubKey = "AwEAAaHIwpx3w4VHKi6i1LHnTaWeHCL154Jug0Rtc9ji5qwPXpBo6A5sRv7cSsPQKPIwxLpyCrbJ4mr2L0EPOdvP6z6YfljK2ZmTbogU9aSU2fiq/4wjxbdkLyoDVgtO+JsxNN4bjr4WcWhsmk1Hg93FV9ZpkWb0Tbad8DFqNDzr//kZ"

	out.Answer[0] = key
	msg, ok = out.Pack()
	if !ok {
		t.Log("Failed to pack msg with DNSKEY")
		t.Fail()
	}

	if !in.Unpack(msg) {
		t.Log("Failed to unpack msg with DNSKEY")
		t.Fail()
	}

	sig := new(RR_RRSIG)
	sig.Hdr = RR_Header{Name: "miek.nl.", Rrtype: TypeRRSIG, Class: ClassINET, Ttl: 3600}
	sig = &RR_RRSIG{TypeCovered: TypeDNSKEY, Algorithm: AlgRSASHA1, Labels: 2,
		OrigTtl: 3600, Expiration: 4000, Inception: 4000, KeyTag: 34641, SignerName: "miek.nl.",
		Signature: "AwEAAaHIwpx3w4VHKi6i1LHnTaWeHCL154Jug0Rtc9ji5qwPXpBo6A5sRv7cSsPQKPIwxLpyCrbJ4mr2L0EPOdvP6z6YfljK2ZmTbogU9aSU2fiq/4wjxbdkLyoDVgtO+JsxNN4bjr4WcWhsmk1Hg93FV9ZpkWb0Tbad8DFqNDzr//kZ"}

	out.Answer[0] = sig
	msg, ok = out.Pack()
	if !ok {
		t.Log("Failed to pack msg with RRSIG")
		t.Fail()
	}

	if !in.Unpack(msg) {
		t.Log("Failed to unpack msg with RRSIG")
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
