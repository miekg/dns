package dns

import (
	"net"
	"testing"
)

func TestPackUnpack(t *testing.T) {
	out := new(Msg)
	out.Answer = make([]RR, 1)
	key := new(RR_DNSKEY)
	key = &RR_DNSKEY{Flags: 257, Protocol: 3, Algorithm: RSASHA1}
	key.Hdr = RR_Header{Name: "miek.nl.", Rrtype: TypeDNSKEY, Class: ClassINET, Ttl: 3600}
	key.PublicKey = "AwEAAaHIwpx3w4VHKi6i1LHnTaWeHCL154Jug0Rtc9ji5qwPXpBo6A5sRv7cSsPQKPIwxLpyCrbJ4mr2L0EPOdvP6z6YfljK2ZmTbogU9aSU2fiq/4wjxbdkLyoDVgtO+JsxNN4bjr4WcWhsmk1Hg93FV9ZpkWb0Tbad8DFqNDzr//kZ"

	out.Answer[0] = key
	msg, ok := out.Pack()
	if !ok {
		t.Log("Failed to pack msg with DNSKEY")
		t.Fail()
	}
	in := new(Msg)
	if !in.Unpack(msg) {
		t.Log("Failed to unpack msg with DNSKEY")
		t.Fail()
	}

	sig := new(RR_RRSIG)
	sig = &RR_RRSIG{TypeCovered: TypeDNSKEY, Algorithm: RSASHA1, Labels: 2,
		OrigTtl: 3600, Expiration: 4000, Inception: 4000, KeyTag: 34641, SignerName: "miek.nl.",
		Signature: "AwEAAaHIwpx3w4VHKi6i1LHnTaWeHCL154Jug0Rtc9ji5qwPXpBo6A5sRv7cSsPQKPIwxLpyCrbJ4mr2L0EPOdvP6z6YfljK2ZmTbogU9aSU2fiq/4wjxbdkLyoDVgtO+JsxNN4bjr4WcWhsmk1Hg93FV9ZpkWb0Tbad8DFqNDzr//kZ"}
	sig.Hdr = RR_Header{Name: "miek.nl.", Rrtype: TypeRRSIG, Class: ClassINET, Ttl: 3600}

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
}

func TestPackUnpack2(t *testing.T) {
	m := new(Msg)
	m.Extra = make([]RR, 1)
	m.Answer = make([]RR, 1)
	dom := "miek.nl."
	rr := new(RR_A)
	rr.Hdr = RR_Header{Name: dom, Rrtype: TypeA, Class: ClassINET, Ttl: 0}
	rr.A = net.IPv4(127, 0, 0, 1)

	x := new(RR_TXT)
	x.Hdr = RR_Header{Name: dom, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}
	x.Txt = []string{"heelalaollo"}

	m.Extra[0] = x
	m.Answer[0] = rr
	_, ok := m.Pack()
	if !ok {
		t.Log("Packing failed")
		t.Fail()
		return
	}
}

func TestEDNS_RR(t *testing.T) {
	edns := new(RR_OPT)
	edns.Hdr.Name = "." // must . be for edns
	edns.Hdr.Rrtype = TypeOPT
	edns.Hdr.Class = ClassINET
	edns.Hdr.Ttl = 3600
	edns.Option = make([]Option, 1)
	edns.Option[0].Code = OptionCodeNSID
	edns.Option[0].Data = "lalalala"
	//t..Logf("%v\n", edns)
}
