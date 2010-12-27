package dns

import (
	"testing"
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
        // You can handle an OTP RR as any other, but there
        // are some convience functions
        edns.UDPSize(4096, true)
        edns.DoBit(true, true)
//        edns.Nsid("mieks-server", true) 
//	edns.Hdr.Class = ClassINET
//	edns.Hdr.Ttl = 3600
	// no options for now
	//      edns.Option = make([]Option, 1)
	//      edns.Option[0].Code = OptionCodeNSID
	//      edns.Option[0].Data = "lalalala"

	// ask something
	m.Question[0] = Question{"nlnetlabs.nl", TypeSOA, ClassINET}
	m.Extra[0] = edns

	ch <- DnsMsg{m, nil}
	in := <-ch

	if in.Dns.Rcode != RcodeSuccess {
		t.Log("Failed to get an valid answer")
		t.Fail()
	}
        fmt.Printf("recv: %v\n", in.Dns) // TODO remove print (MG)
	ch <- DnsMsg{nil, nil}
        <-ch    // wait for ch to close channel
}
