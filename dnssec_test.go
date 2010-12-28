package dns

import (
	"testing"
)

func TestSecure(t *testing.T) {
// once this was valid
        soa := new(RR_SOA)
	soa.Hdr = RR_Header{"miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
        soa.Mbox = "miekg.atoom.net."
        soa.Serial = 1293513905
        soa.Refresh = 14400
        soa.Retry = 3600
        soa.Expire = 604800
        soa.Minttl = 86400

	sig := new(RR_RRSIG)
        sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = TypeSOA
	sig.Algorithm = AlgRSASHA256
	sig.Labels = 2
        sig.Expiration = 1296098705 // date '+%s' -d"2011-01-27 04:25:05
        sig.Inception = 1293506705
	sig.OrigTtl = 14400
	sig.KeyTag = 12051
	sig.SignerName = "miek.nl."
	sig.Sig = "kLq/5oFy3Sh5ZxPGFMCyHq8MtN6E17R1Ln9+bJ2Q76YYAxFE8Xlie33A1GFctH2uhzRzJKuP/JSjUkrvGk2rjBm32z9zXtZsKx/4yV0da2nLRm44NOmX6gsP4Yia8mdqPUajjkyLzAzU2bevtesJm0Z65AcmPdq3tUZODdRAcng="

	key := new(RR_DNSKEY)
	key.Hdr.Name = "miek.nl."
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = AlgRSASHA256
	key.PubKey = "AwEAAcNEU67LJI5GEgF9QLNqLO1SMq1EdoQ6E9f85ha0k0ewQGCblyW2836GiVsm6k8Kr5ECIoMJ6fZWf3CQSQ9ycWfTyOHfmI3eQ/1Covhb2y4bAmL/07PhrL7ozWBW3wBfM335Ft9xjtXHPy7ztCbV9qZ4TVDTW/Iyg0PiwgoXVesz"

        // It should validate, at least this month dec 2010
        if ! sig.Secure([]RR{soa}, key) {
                t.Log("Failure to validate")
                t.Fail()
        }
}
