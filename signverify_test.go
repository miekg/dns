package dns

import (
	"testing"
	"fmt"
	"os"
)

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
