package dns

import (
	"testing"
)

func TestResolver(t *testing.T) {
	res := new(Resolver)
	res.Servers = []string{"127.0.0.1"}

	m := new(Msg)
	m.MsgHdr.RecursionDesired = true //only set this bit
	m.Question = make([]Question, 1)

	// ask something
	m.Question[0] = Question{"miek.nl", TypeSOA, ClassINET}
	in, _ := res.Query(m)

	if in != nil && in.Rcode != RcodeSuccess {
		t.Log("Failed to get an valid answer")
		t.Fail()
		t.Logf("%v\n", in)
	}

	// ask something
	m.Question[0] = Question{"www.nlnetlabs.nl", TypeRRSIG, ClassINET}
        in, _ = res.Query(m)

	if in != nil && in.Rcode != RcodeSuccess {
		t.Log("Failed to get an valid answer")
		t.Fail()
		t.Logf("%v\n", in)
	}
}

func TestResolverEdns(t *testing.T) {
	res := new(Resolver)
	res.Servers = []string{"127.0.0.1"}
	res.Timeout = 2
	res.Attempts = 1

	m := new(Msg)
	m.MsgHdr.RecursionDesired = true //only set this bit
	m.Question = make([]Question, 1)

	// Add EDNS rr
	edns := new(RR_OPT)
	edns.Hdr.Name = "." // must . be for edns
	edns.Hdr.Rrtype = TypeOPT
	// You can handle an OTP RR as any other, but there
	// are some convience functions
	edns.SetUDPSize(2048)
	edns.SetDo()
	edns.Option = make([]Option, 1)
	edns.SetNsid("") // Empty to request it

	// ask something
	m.Question[0] = Question{"powerdns.nl", TypeDNSKEY, ClassINET}
	m.Extra = make([]RR, 1)
	m.Extra[0] = edns

	in, _ := res.Query(m)
	if in != nil {
		if in.Rcode != RcodeSuccess {
			t.Logf("%v\n", in)
			t.Log("Failed to get an valid answer")
			t.Fail()
		}
	}
}

func TestResolverTsig(t *testing.T) {
	res := new(Resolver)
	res.Servers = []string{"127.0.0.1"}
	res.Timeout = 2
	res.Attempts = 1

	m := new(Msg)
	m.MsgHdr.RecursionDesired = true //only set this bit
	m.Question = make([]Question, 1)

	// ask something
	m.Question[0] = Question{"powerdns.nl", TypeDNSKEY, ClassINET}
	m.Extra = make([]RR, 1)
	m.SetId()

	tsig := new(RR_TSIG)
	tsig.Hdr.Name = "miek.nl" // for tsig this is the key's name
	tsig.Hdr.Rrtype = TypeTSIG
	tsig.Hdr.Class = ClassANY
	tsig.Hdr.Ttl = 0
	tsig.Generate(m, "geheim")
	// Add it to the msg
	m.Extra[0] = tsig

	in, _ := res.Query(m)
	if in != nil {
		if in.Rcode != RcodeSuccess {
			t.Logf("%v\n", in)
			t.Log("Failed to get an valid answer")
		//	t.Fail()
		}
	}
}

func TestAXFR(t *testing.T) {
	res := new(Resolver)
	res.Servers = []string{"127.0.0.1"}
	m := new(Msg)
	m.Question = make([]Question, 1)
	m.Question[0] = Question{"miek.nl", TypeAXFR, ClassINET}

        ch := make(chan *Msg)
        go res.Axfr(m, ch)
	for x := range ch {
		var _ = x
		/* fmt.Printf("%v\n",dm.Dns) */
	}
	/* channel is closed by Axfr() */
}

func TestFromFile(t *testing.T) {
	res := new(Resolver)
	res.FromFile("/etc/resolv.conf")
	m := new(Msg)
	m.Question = make([]Question, 1)
	m.Question[0] = Question{"a.miek.nl", TypeA, ClassINET}

	in, _ := res.Query(m)
	if in != nil {
		if in.Rcode != RcodeSuccess {
			t.Log("Failed to get an valid answer")
			t.Fail()
		}
	}
}
