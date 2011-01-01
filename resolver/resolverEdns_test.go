package resolver

import (
	"testing"
        "dns"
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
	edns.Hdr.Name = "."  // must . be for edns
	edns.Hdr.Rrtype = dns.TypeOPT
        // You can handle an OTP RR as any other, but there
        // are some convience functions
        edns.UDPSize(4096, true)
        edns.DoBit(true, true)
//        edns.Nsid("mieks-server", true) 
	// no options for now
	//      edns.Option = make([]Option, 1)
	//      edns.Option[0].Code = OptionCodeNSID
	//      edns.Option[0].Data = "lalalala"

	// ask something
	m.Question[0] = dns.Question{"nlnetlabs.nl", dns.TypeSOA, dns.ClassINET}
	m.Extra[0] = edns

	ch <- DnsMsg{m, nil}
	in := <-ch
////        t.Fail()
  //      t.Log("%v\n", in.Dns)

	if in.Dns.Rcode != dns.RcodeSuccess {
		t.Log("Failed to get an valid answer")
		t.Fail()
	}
	ch <- DnsMsg{nil, nil}
        <-ch    // wait for ch to close channel
}
