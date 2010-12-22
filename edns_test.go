package dns

// Test EDNS RR records

import (
	"testing"
)

func TestEDNS_RR(t *testing.T) {
        edns := new(RR_EDNS0)
        edns.Hdr.Name = "miek.nl."      // must . be for edns
        edns.Hdr.Rrtype = TypeOPT
        edns.Hdr.Class = ClassINET
        edns.Hdr.Ttl = 3600
        edns.Option = make([]Option, 1)
        edns.Option[0].Code = OptionCodeNSID
        edns.Option[0].Data = "lalalala"
        //fmt.Printf("%s\n", edns)
}
