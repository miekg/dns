package dns

import (
	"testing"
	"net"
)

func main() {
	out := new(dns.Msg)
	r := new(dns.RR_AAAA)
	r.AAAA = net.ParseIP("2001:7b8:206:1:200:39ff:fe59:b187").To16()
	r.Hdr.Name = "a.miek.nl"
	r.Hdr.Rrtype = dns.TypeAAAA
	r.Hdr.Class = dns.ClassINET
	r.Hdr.Ttl = 3600
	out.Answer = make([]dns.RR, 1)
	out.Answer[0] = r

	msg, err := out.Pack()
	if err != nil {
		t.Log("Failed to pack msg with AAAA")
		t.Fail()
	}

	in := new(dns.Msg)
	if in.Unpack(msg) != true {
		t.Log("Failed to unpack msg with AAAA")
		t.Fail()
	}
	fmt.Printf("%v\n", in)

	sig := new(dns.RR_RRSIG)
	sig.Hdr.Name = "miek.nl."
	sig.Hdr.Rrtype = dns.TypeRRSIG
	sig.Hdr.Class = dns.ClassINET
	sig.Hdr.Ttl = 3600
	sig.TypeCovered = dns.TypeDNSKEY
	sig.Algorithm = dns.AlgRSASHA1
	sig.OrigTtl = 4000
	sig.Expiration = 1000
	sig.Inception = 800
	sig.KeyTag = 34641
	sig.SignerName = "miek.nl."
	sig.Sig = "AwEAAaHIwpx3w4VHKi6i1LHnTaWeHCL154Jug0Rtc9ji5qwPXpBo6A5sRv7cSsPQKPIwxLpyCrbJ4mr2L0EPOdvP6z6YfljK2ZmTbogU9aSU2fiq/4wjxbdkLyoDVgtO+JsxNN4bjr4WcWhsmk1Hg93FV9ZpkWb0Tbad8DFq NDzr//kZ"

	out.Answer[0] = sig
	msg, err = out.Pack()
	if err != nil {
		t.Log("Failed to pack msg with RRSIG")
		t.Fail()
	}

	if in.Unpack(msg) != true {
		t.Log("Failed to unpack msg with RRSIG")
		t.Fail()
	}
	fmt.Printf("%v\n", in)



}
