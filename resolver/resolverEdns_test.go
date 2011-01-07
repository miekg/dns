package resolver

import (
	"testing"
	"dns"
	"fmt"
)

func TestResolverEdns(t *testing.T) {
	res := new(Resolver)
	ch := res.NewQuerier()

	res.Servers = []string{"127.0.0.1"}
	res.Timeout = 2
	res.Attempts = 1

	m := new(dns.Msg)
	m.MsgHdr.RecursionDesired = true //only set this bit
	m.Question = make([]dns.Question, 1)
	m.Extra = make([]dns.RR, 1)

	// Add EDNS rr
	edns := new(dns.RR_OPT)
	edns.Hdr.Name = "." // must . be for edns
	edns.Hdr.Rrtype = dns.TypeOPT
	// You can handle an OTP RR as any other, but there
	// are some convience functions
	edns.SetUDPSize(4096)
	edns.SetDo()
	edns.Option = make([]dns.Option, 1)
	edns.SetNsidToHex("") // Empty to request it

	// ask something
	m.Question[0] = dns.Question{"miek.nl", dns.TypeA, dns.ClassINET}
	m.Extra[0] = edns

	ch <- DnsMsg{m, nil}
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
	ch <- DnsMsg{nil, nil}
	<-ch // wait for ch to close channel
}
