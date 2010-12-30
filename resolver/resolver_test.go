package resolver

import (
	"testing"
        "dns"
)


func TestResolver(t *testing.T) {
	res := new(Resolver)
	ch := NewQuerier(res)

	res.Servers = []string{"127.0.0.1"}

	m := new(dns.Msg)
	m.MsgHdr.Recursion_desired = true //only set this bit
	m.Question = make([]dns.Question, 1)

	// ask something
	m.Question[0] = dns.Question{"miek.nl", dns.TypeSOA, dns.ClassINET}
	ch <- DnsMsg{m, nil}
	in := <-ch

	if in.Dns.Rcode != dns.RcodeSuccess {
		t.Log("Failed to get an valid answer")
		t.Fail()
	        t.Logf("%v\n", in)
	}

	// ask something
	m.Question[0] = dns.Question{"www.nlnetlabs.nl", dns.TypeRRSIG, dns.ClassINET}
	ch <- DnsMsg{m, nil}
	in = <-ch

	if in.Dns.Rcode != dns.RcodeSuccess {
		t.Log("Failed to get an valid answer")
		t.Fail()
	        t.Logf("%v\n", in)
	}

	ch <- DnsMsg{nil, nil}
        <-ch
}
