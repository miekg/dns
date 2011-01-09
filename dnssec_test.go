package dns

import (
	"testing"
        "fmt"
        "os"
)

func TestSecure(t *testing.T) {
// once this was valid
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
        // UTC LUL!
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
