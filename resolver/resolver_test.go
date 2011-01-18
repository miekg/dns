package resolver

import (
	"testing"
	"dns"
)

func TestResolver(t *testing.T) {
	res := new(Resolver)
	ch := res.NewQuerier()

	res.Servers = []string{"127.0.0.1"}

	m := new(dns.Msg)
	m.MsgHdr.RecursionDesired = true //only set this bit
	m.Question = make([]dns.Question, 1)

	// ask something
	m.Question[0] = dns.Question{"miek.nl", dns.TypeSOA, dns.ClassINET}
	ch <- Msg{m, nil, nil}
	in := <-ch

	if in.Dns != nil && in.Dns.Rcode != dns.RcodeSuccess {
		t.Log("Failed to get an valid answer")
		t.Fail()
		t.Logf("%v\n", in)
	}

	// ask something
	m.Question[0] = dns.Question{"www.nlnetlabs.nl", dns.TypeRRSIG, dns.ClassINET}
	ch <- Msg{m, nil, nil}
	in = <-ch

	if in.Dns != nil && in.Dns.Rcode != dns.RcodeSuccess {
		t.Log("Failed to get an valid answer")
		t.Fail()
		t.Logf("%v\n", in)
	}

	ch <- Msg{}
	<-ch
}

func TestResolverEdns(t *testing.T) {
	res := new(Resolver)
	ch := res.NewQuerier()

	res.Servers = []string{"127.0.0.1"}
	res.Timeout = 2
	res.Attempts = 1

	m := new(dns.Msg)
	m.MsgHdr.RecursionDesired = true //only set this bit
	m.Question = make([]dns.Question, 1)

	// Add EDNS rr
	edns := new(dns.RR_OPT)
	edns.Hdr.Name = "." // must . be for edns
	edns.Hdr.Rrtype = dns.TypeOPT
	// You can handle an OTP RR as any other, but there
	// are some convience functions
	edns.SetUDPSize(2048)
	edns.SetDo()
	edns.Option = make([]dns.Option, 1)
	edns.SetNsid("") // Empty to request it

	// ask something
	m.Question[0] = dns.Question{"powerdns.nl", dns.TypeDNSKEY, dns.ClassINET}
	m.Extra = make([]dns.RR, 1)
	m.Extra[0] = edns

	ch <- Msg{m, nil, nil}
	in := <-ch
	if in.Dns != nil {
		if in.Dns.Rcode != dns.RcodeSuccess {
			t.Logf("%v\n", in.Dns)
			t.Log("Failed to get an valid answer")
			t.Fail()
		}
	}
	ch <- Msg{}
	<-ch // wait for ch to close channel
}

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
	tsig.Hdr.Name = "miek.nl" // for tsig this is the key's name
	tsig.Hdr.Rrtype = dns.TypeTSIG
	tsig.Hdr.Class = dns.ClassANY
	tsig.Hdr.Ttl = 0
	tsig.Generate(m, "geheim")
	// Add it to the msg
	m.Extra[0] = tsig

	ch <- Msg{m, nil, nil}
	in := <-ch
	if in.Dns != nil {
		if in.Dns.Rcode != dns.RcodeSuccess {
			t.Logf("%v\n", in.Dns)
			t.Log("Failed to get an valid answer")
		//	t.Fail()
		}
	}
	ch <- Msg{}
	<-ch // wait for ch to close channel
}

func TestAXFR(t *testing.T) {
	res := new(Resolver)
	ch := res.NewXfer()

	res.Servers = []string{"127.0.0.1"}
	m := new(dns.Msg)
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{"miek.nl", dns.TypeAXFR, dns.ClassINET}
	//m.Question[0] = dns.Question{"atoom.net", dns.TypeAXFR, dns.ClassINET}

	ch <- Msg{m, nil, nil}
	for dm := range ch {
		var _ = dm
		/* fmt.Printf("%v\n",dm.Dns) */
	}
	/* channel is closed by NewXfer() */
}

func TestFromFile(t *testing.T) {
	res := new(Resolver)
	res.FromFile("/etc/resolv.conf")
	ch := res.NewQuerier()
	m := new(dns.Msg)
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{"a.miek.nl", dns.TypeA, dns.ClassINET}

	ch <- Msg{m, nil, nil}
	in := <-ch
	if in.Dns != nil {
		if in.Dns.Rcode != dns.RcodeSuccess {
			t.Log("Failed to get an valid answer")
			t.Fail()
		}
	}
}
