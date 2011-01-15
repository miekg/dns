package dns

import (
	"testing"
        "fmt"
)

func TestKeyGenRSA(t *testing.T) {
	key := new(RR_DNSKEY)
	key.Hdr.Name = "miek.nl."
        key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 3600
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = AlgRSASHA256
        length := 2048
        priv, _ := key.Generate(length)

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
        sig.KeyTag = key.KeyTag()
        sig.SignerName = "miek.nl."

        sig.Sign(priv, []RR{soa})

        s := key.PrivateKeyString(priv)
        fmt.Printf("%s\n", s)

        fmt.Printf("%v\n", sig)
}
