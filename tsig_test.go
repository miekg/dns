package dns

import (
	"testing"
        "fmt"
)

func TestTsig(t *testing.T) {
	tsig := new(RR_TSIG)
	tsig.Hdr.Name = "miek.nl"       // for tsig this is the key's name
	tsig.Hdr.Rrtype = TypeTSIG
	tsig.Hdr.Class = ClassANY
	tsig.Hdr.Ttl = 0

        out := new(Msg)
        out.MsgHdr.RecursionDesired = true
        out.Question = make([]Question, 1)
        out.Question[0] = Question{"miek.nl", TypeSOA, ClassINET}

        ok := tsig.GenerateMAC(out, "geheim")
        if !ok {
                t.Log("Failed")
                t.Fail()
        }
        fmt.Printf("%v\n", tsig)

        // Having the TSIG record, it must now be added to the msg
        // in the extra section
        out.Extra = make([]RR, 1)
        out.Extra[0] = tsig

        fmt.Printf("%v\n", out)
}
