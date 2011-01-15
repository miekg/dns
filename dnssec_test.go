package dns

import (
	"testing"
        "fmt"
        "os"
)

func TestSecure(t *testing.T) {
        soa := new(RR_SOA)
	soa.Hdr = RR_Header{"miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
        soa.Mbox = "miekg.atoom.net."
        soa.Serial = 1293945905
        soa.Refresh = 14400
        soa.Retry = 3600
        soa.Expire = 604800
        soa.Minttl = 86400

	sig := new(RR_RRSIG)
        sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = TypeSOA
	sig.Algorithm = AlgRSASHA256
	sig.Labels = 2
        sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
        sig.Inception = 1293942305 // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.OrigTtl = 14400
	sig.KeyTag = 12051
	sig.SignerName = "miek.nl."
	sig.Signature = "oMCbslaAVIp/8kVtLSms3tDABpcPRUgHLrOR48OOplkYo+8TeEGWwkSwaz/MRo2fB4FxW0qj/hTlIjUGuACSd+b1wKdH5GvzRJc2pFmxtCbm55ygAh4EUL0F6U5cKtGJGSXxxg6UFCQ0doJCmiGFa78LolaUOXImJrk6AFrGa0M="

	key := new(RR_DNSKEY)
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = AlgRSASHA256
	key.PubKey = "AwEAAcNEU67LJI5GEgF9QLNqLO1SMq1EdoQ6E9f85ha0k0ewQGCblyW2836GiVsm6k8Kr5ECIoMJ6fZWf3CQSQ9ycWfTyOHfmI3eQ/1Covhb2y4bAmL/07PhrL7ozWBW3wBfM335Ft9xjtXHPy7ztCbV9qZ4TVDTW/Iyg0PiwgoXVesz"

        fmt.Fprintf(os.Stderr, "%v\n%v\n", sig, soa)
        // It should validate. Period is checked seperately, so this will keep on working
        if ! sig.Verify(key, []RR{soa}) {
                t.Log("Failure to validate")
                t.Fail()
        } else {
                println("It validates!!")
        }
}

func TestSignature(t *testing.T) {
	sig := new(RR_RRSIG)
	sig.Hdr.Name = "miek.nl."
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
	sig.Signature = "AwEAAaHIwpx3w4VHKi6i1LHnTaWeHCL154Jug0Rtc9ji5qwPXpBo6A5sRv7cSsPQKPIwxLpyCrbJ4mr2L0EPOdvP6z6YfljK2ZmTbogU9aSU2fiq/4wjxbdkLyoDVgtO+JsxNN4bjr4WcWhsmk1Hg93FV9ZpkWb0Tbad8DFqNDzr//kZ"

	// Should not be valid
	if sig.PeriodOK() {
		t.Log("Should not be valid")
		t.Fail()
	}

	sig.Inception = 315565800   //Tue Jan  1 10:10:00 CET 1980
	sig.Expiration = 4102477800 //Fri Jan  1 10:10:00 CET 2100
	if !sig.PeriodOK() {
		t.Log("Should be valid")
		t.Fail()
	}
}

func TestSignVerify(t *testing.T) {
	// The record we want to sign
	soa := new(RR_SOA)
	soa.Hdr = RR_Header{"miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// With this key
	key := new(RR_DNSKEY)
        key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = AlgRSASHA256
	privkey, _ := key.Generate(512)
        fmt.Fprintf(os.Stderr, "Key tag: %d\n", key.KeyTag())

	// Fill in the values of the Sig, before signing
	sig := new(RR_RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = LabelCount(soa.Hdr.Name)
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = AlgRSASHA256

	// zal wel goed zijn
	if !sig.Sign(privkey, []RR{soa}) {
		t.Log("Failure to sign the SOA record")
		t.Fail()
	}
        fmt.Fprintf(os.Stderr, "%v\n%v\n%v\n", soa, key, sig)
	if !sig.Verify(key, []RR{soa}) {
		t.Log("Failure to validate")
		t.Fail()
	} else {
		println("It validates!!")
	}
}
