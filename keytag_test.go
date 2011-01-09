package dns

import (
	"testing"
)

func TestTag(t *testing.T) {
	key := new(RR_DNSKEY)
	key.Hdr.Name = "miek.nl."
        key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 3600
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = AlgRSASHA256
	key.PubKey = "AwEAAcNEU67LJI5GEgF9QLNqLO1SMq1EdoQ6E9f85ha0k0ewQGCblyW2836GiVsm6k8Kr5ECIoMJ6fZWf3CQSQ9ycWfTyOHfmI3eQ/1Covhb2y4bAmL/07PhrL7ozWBW3wBfM335Ft9xjtXHPy7ztCbV9qZ4TVDTW/Iyg0PiwgoXVesz"

        tag := key.KeyTag()
        if tag != 12051 {
                t.Logf("%v\n", key)
                t.Logf("Wrong key tag: %d\n", tag)
                t.Fail()
        }
}
