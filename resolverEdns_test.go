package dns

import (
	"testing"
	"time"
	"fmt"
)

func TestResolverEdns(t *testing.T) {
	res := new(Resolver)
	ch := NewQuerier(res)

	res.Servers = []string{"127.0.0.1"}
	res.Timeout = 2
	res.Attempts = 1

	m := new(Msg)
	m.MsgHdr.Recursion_desired = true //only set this bit
	m.Question = make([]Question, 1)
	m.Extra = make([]RR, 1)

	// Add EDNS rr
	edns := new(RR_OPT)
	edns.Hdr.Name = "."  // must . be for edns
	edns.Hdr.Rrtype = TypeOPT
	edns.Hdr.Class = ClassINET
	edns.Hdr.Ttl = 3600
	// no options for now
	//      edns.Option = make([]Option, 1)
	//      edns.Option[0].Code = OptionCodeNSID
	//      edns.Option[0].Data = "lalalala"

	// ask something
	m.Question[0] = Question{"miek.nl", TypeSOA, ClassINET}
	m.Extra[0] = edns

	fmt.Printf("Sending: %v\n", m)

	ch <- DnsMsg{m, nil}
	in := <-ch

	if in.Dns.Rcode != RcodeSuccess {
		t.Log("Failed to get an valid answer")
		t.Fail()
	}
	fmt.Printf("Recv: %v\n", in.Dns)

	ch <- DnsMsg{nil, nil}
	time.Sleep(1.0e9)
}
