package dns

import "testing"

func TestDOHConn(t *testing.T) {
	const addrstr = "https://dns.cloudflare.com"

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

	cl := &Client{Net: "https"}

	cn, err := cl.Dial(addrstr)
	if err != nil {
		t.Fatalf("failed to dial %s: %v", addrstr, err)
	}

	err = cn.WriteMsg(m)
	if err != nil {
		t.Errorf("failed to exchange: %v", err)
	}
	r, err := cn.ReadMsg()
	if err != nil {
		t.Fatalf("failed to get a valid answer: %v", err)
	}
	if r == nil || r.Rcode != RcodeSuccess {
		t.Errorf("failed to get an valid answer\n%v", r)
	}

	t.Log(r)
}
