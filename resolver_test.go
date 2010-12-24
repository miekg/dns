package dns

import (
	"testing"
	"time"
)


func TestResolver(t *testing.T) {
	res := new(Resolver)
	ch := NewQuerier(res)

	res.Servers = []string{"127.0.0.1"}
	res.Timeout = 2
	res.Attempts = 1

	m := new(Msg)
	m.MsgHdr.Recursion_desired = true //only set this bit
	m.Question = make([]Question, 1)

	// ask something
	m.Question[0] = Question{"miek.nl", TypeSOA, ClassINET}
	ch <- DnsMsg{m, nil}
	in := <-ch

	if in.Dns.Rcode != RcodeSuccess {
		t.Log("Failed to get an valid answer")
		t.Fail()
	        t.Logf("%v\n", in)
	}

	// ask something
	m.Question[0] = Question{"www.nlnetlabs.nl", TypeRRSIG, ClassINET}
	ch <- DnsMsg{m, nil}
	in = <-ch

	if in.Dns.Rcode != RcodeSuccess {
		t.Log("Failed to get an valid answer")
		t.Fail()
	        t.Logf("%v\n", in)
	}

	ch <- DnsMsg{nil, nil}
	time.Sleep(0.5e9)
}
