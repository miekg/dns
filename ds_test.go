package dns

import (
	"testing"
        "strings"
)

func TestKeyToDS(t *testing.T) {
	key := new(RR_DNSKEY)
	key.Hdr.Name = "miek.nl"
        key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 3600
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = AlgRSASHA256
	key.PubKey = "AwEAAcNEU67LJI5GEgF9QLNqLO1SMq1EdoQ6E9f85ha0k0ewQGCblyW2836GiVsm6k8Kr5ECIoMJ6fZWf3CQSQ9ycWfTyOHfmI3eQ/1Covhb2y4bAmL/07PhrL7ozWBW3wBfM335Ft9xjtXHPy7ztCbV9qZ4TVDTW/Iyg0PiwgoXVesz"

        ds := key.ToDS(HashSHA1)
        if strings.ToUpper(ds.Digest) != "B5121BDB5B8D86D0CC5FFAFBAAABE26C3E20BAC1" {
                t.Logf("Wrong DS digest for Sha1\n%v\n", ds)
                t.Fail()
        }
}
