package dns

import (
	"testing"
	"time"
)

func TestPackUnpack(t *testing.T) {
	out := new(Msg)
	out.Answer = make([]RR, 1)
	key := new(RR_DNSKEY)
	key.Hdr = RR_Header{Name: "miek.nl.", Rrtype: TypeDNSKEY, Class: ClassINET, Ttl: 3600}
	key = &RR_DNSKEY{Flags: 257, Protocol: 3, Algorithm: AlgRSASHA1}
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

func TestTsig(t *testing.T) {
	tsig := new(RR_TSIG)
	tsig.Hdr.Name = "miek.nl." // for tsig this is the key's name
	tsig.Hdr.Rrtype = TypeTSIG
	tsig.Hdr.Class = ClassANY
	tsig.Hdr.Ttl = 0
	tsig.Fudge = 300
	tsig.TimeSigned = uint64(time.Seconds())

	out := new(Msg)
	out.MsgHdr.RecursionDesired = true
	out.Question = make([]Question, 1)
	out.Question[0] = Question{"miek.nl.", TypeSOA, ClassINET}

	ok := tsig.Generate(out, "awwLOtRfpGE+rRKF2+DEiw==")
	if !ok {
		t.Log("Failed")
		t.Fail()
	}

	// Having the TSIG record, it must now be added to the msg
	// in the extra section
	out.Extra = make([]RR, 1)
	out.Extra[0] = tsig
}
