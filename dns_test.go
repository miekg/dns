package dns

import (
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

/*
func TestTsig(t *testing.T) {
        tsig := new(Tsig)
        tsig.Name = "axfr."
        tsig.Algorithm = HmacMD5
        tsig.Fudge = 300
        tsig.TimeSigned = uint64(time.Seconds())
        tsig.Secret = "so6ZGir4GPAqINNh9U5c3A=="

        // Perform a TSIG from miek.nl
        m := new(Msg)
        m.Question = make([]Question, 1)
        m.Question[0] = Question{"miek.nl.", TypeAXFR, ClassINET}
        m.Id = Id()

        res := new(Resolver)
        res.FromFile("/etc/resolv.conf")
        res.Servers = []string{"85.223.71.124"}
        res.Tcp = true

        c := make(chan Xfr)
        go res.XfrTsig(m, tsig, c)
        for x := range c {
                if x.Err != nil {
                        t.Logf("Failed Xfr from miek.nl %v\n", x.Err)
                        t.Fail()
                }
        }

        tsig.Secret = "ZGZqc2tmZAo="
        // Do it again, must fail
        c = make(chan Xfr) // Reopen the channel
        go res.XfrTsig(m, tsig, c)
        ok := false
        for x := range c {
                if x.Err != nil {
                        ok = true
                }
        }
        if ok == true {
                t.Logf("AXFR with wrong secret should fail")
                t.Fail()
        }
}
*/
