package dns

import (
	"testing"
)

func TestSignature(t *testing.T) {
	sig := new(RR_RRSIG)
	sig.Hdr.Name = "miek.nl."
	sig.Hdr.Rrtype = TypeRRSIG
	sig.Hdr.Class = ClassINET
	sig.Hdr.Ttl = 3600
	sig.TypeCovered = TypeDNSKEY
	sig.Algorithm = AlgRSASHA1
	sig.Labels = 2
	sig.OrigTtl = 4000
	sig.Expiration = 1000 //Thu Jan  1 02:06:40 CET 1970
	sig.Inception = 800   //Thu Jan  1 01:13:20 CET 1970
	sig.KeyTag = 34641
	sig.SignerName = "miek.nl."
	sig.Sig = "AwEAAaHIwpx3w4VHKi6i1LHnTaWeHCL154Jug0Rtc9ji5qwPXpBo6A5sRv7cSsPQKPIwxLpyCrbJ4mr2L0EPOdvP6z6YfljK2ZmTbogU9aSU2fiq/4wjxbdkLyoDVgtO+JsxNN4bjr4WcWhsmk1Hg93FV9ZpkWb0Tbad8DFqNDzr//kZ"

	// Should not be valid
	if sig.PeriodOK() {
		t.Log("Should not be valid")
		t.Fail()
	}

        sig.Inception = 315565800 //Tue Jan  1 10:10:00 CET 1980
        sig.Expiration = 4102477800 //Fri Jan  1 10:10:00 CET 2100
        if ! sig.PeriodOK() {
                t.Log("Should be valid")
                t.Fail()
        }
}
