package resolver

import (
	"testing"
	"dns"
	"fmt"
)

func TestResolverTsig(t *testing.T) {
	res := new(Resolver)
	ch := res.NewQuerier()

	res.Servers = []string{"127.0.0.1"}
	res.Timeout = 2
	res.Attempts = 1

	m := new(dns.Msg)
	m.MsgHdr.RecursionDesired = true //only set this bit
	m.Question = make([]dns.Question, 1)

	// ask something
	m.Question[0] = dns.Question{"powerdns.nl", dns.TypeDNSKEY, dns.ClassINET}
	m.Extra = make([]dns.RR, 1)
        m.SetId()

        tsig := new(dns.RR_TSIG)
        tsig.Hdr.Name = "miek.nl"       // for tsig this is the key's name
        tsig.Hdr.Rrtype = dns.TypeTSIG
        tsig.Hdr.Class = dns.ClassANY
        tsig.Hdr.Ttl = 0
        tsig.Generate(m, "geheim")
        // Add it to the msg
        m.Extra[0] = tsig


	ch <- Msg{m, nil}
	in := <-ch
	if in.Dns != nil {
		if in.Dns.Rcode != dns.RcodeSuccess {
			t.Log("Failed to get an valid answer")
			t.Fail()
		}
		fmt.Printf("%v\n", in.Dns)
	} else {
		fmt.Printf("Failed to get a good anwer")
	}
	ch <- Msg{nil, nil}
	<-ch // wait for ch to close channel
}
