package dns

import (
	"testing"
)

func TestTsig(t *testing.T) {
	tsig := new(RR_TSIG)
	tsig.Hdr.Name = "miek.nl"
	tsig.Hdr.Rrtype = TypeTSIG
	tsig.Hdr.Class = ClassANY
	tsig.Hdr.Ttl = 0

        ok := tsig.GenerateMAC()
        if !ok {
                t.Log("Failed")
                t.Fail()
        }
}
