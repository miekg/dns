// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"net"
	"testing"
)

// Query with way to long name
//./q mx bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.bla.miek.nl.miek.nl.miek123.nl.

func TestPackUnpack(t *testing.T) {
	out := new(Msg)
	out.Answer = make([]RR, 1)
	key := new(DNSKEY)
	key = &DNSKEY{Flags: 257, Protocol: 3, Algorithm: RSASHA1}
	key.Hdr = RR_Header{Name: "miek.nl.", Rrtype: TypeDNSKEY, Class: ClassINET, Ttl: 3600}
	key.PublicKey = "AwEAAaHIwpx3w4VHKi6i1LHnTaWeHCL154Jug0Rtc9ji5qwPXpBo6A5sRv7cSsPQKPIwxLpyCrbJ4mr2L0EPOdvP6z6YfljK2ZmTbogU9aSU2fiq/4wjxbdkLyoDVgtO+JsxNN4bjr4WcWhsmk1Hg93FV9ZpkWb0Tbad8DFqNDzr//kZ"

	out.Answer[0] = key
	msg, err := out.Pack()
	if err != nil {
		t.Log("Failed to pack msg with DNSKEY")
		t.Fail()
	}
	in := new(Msg)
	if in.Unpack(msg) != nil {
		t.Log("Failed to unpack msg with DNSKEY")
		t.Fail()
	}

	sig := new(RRSIG)
	sig = &RRSIG{TypeCovered: TypeDNSKEY, Algorithm: RSASHA1, Labels: 2,
		OrigTtl: 3600, Expiration: 4000, Inception: 4000, KeyTag: 34641, SignerName: "miek.nl.",
		Signature: "AwEAAaHIwpx3w4VHKi6i1LHnTaWeHCL154Jug0Rtc9ji5qwPXpBo6A5sRv7cSsPQKPIwxLpyCrbJ4mr2L0EPOdvP6z6YfljK2ZmTbogU9aSU2fiq/4wjxbdkLyoDVgtO+JsxNN4bjr4WcWhsmk1Hg93FV9ZpkWb0Tbad8DFqNDzr//kZ"}
	sig.Hdr = RR_Header{Name: "miek.nl.", Rrtype: TypeRRSIG, Class: ClassINET, Ttl: 3600}

	out.Answer[0] = sig
	msg, err = out.Pack()
	if err != nil {
		t.Log("Failed to pack msg with RRSIG")
		t.Fail()
	}

	if in.Unpack(msg) != nil {
		t.Log("Failed to unpack msg with RRSIG")
		t.Fail()
	}
}

func TestPackUnpack2(t *testing.T) {
	m := new(Msg)
	m.Extra = make([]RR, 1)
	m.Answer = make([]RR, 1)
	dom := "miek.nl."
	rr := new(A)
	rr.Hdr = RR_Header{Name: dom, Rrtype: TypeA, Class: ClassINET, Ttl: 0}
	rr.A = net.IPv4(127, 0, 0, 1)

	x := new(TXT)
	x.Hdr = RR_Header{Name: dom, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}
	x.Txt = []string{"heelalaollo"}

	m.Extra[0] = x
	m.Answer[0] = rr
	_, err := m.Pack()
	if err != nil {
		t.Log("Packing failed")
		t.Fail()
		return
	}
}

func TestBailiwick(t *testing.T) {
	yes := map[string]string{
		"miek.nl": "ns.miek.nl",
		".":       "miek.nl",
	}
	for parent, child := range yes {
		if !IsSubDomain(parent, child) {
			t.Logf("%s should be child of %s\n", child, parent)
			t.Logf("comparelabels %d", CompareDomainName(parent, child))
			t.Logf("lenlabels %d %d", CountLabel(parent), CountLabel(child))
			t.Fail()
		}
	}
	no := map[string]string{
		"www.miek.nl":  "ns.miek.nl",
		"m\\.iek.nl":   "ns.miek.nl",
		"w\\.iek.nl":   "w.iek.nl",
		"p\\\\.iek.nl": "ns.p.iek.nl", // p\\.iek.nl , literal \ in domain name
		"miek.nl":      ".",
	}
	for parent, child := range no {
		if IsSubDomain(parent, child) {
			t.Logf("%s should not be child of %s\n", child, parent)
			t.Logf("comparelabels %d", CompareDomainName(parent, child))
			t.Logf("lenlabels %d %d", CountLabel(parent), CountLabel(child))
			t.Fail()
		}
	}
}

func TestPack(t *testing.T) {
	rr := []string{"US.    86400	IN	NSEC	0-.us. NS SOA RRSIG NSEC DNSKEY TYPE65534"}
	m := new(Msg)
	var err error
	m.Answer = make([]RR, 1)
	for _, r := range rr {
		m.Answer[0], err = NewRR(r)
		if err != nil {
			t.Logf("Failed to create RR: %s\n", err.Error())
			t.Fail()
			continue
		}
		if _, err := m.Pack(); err != nil {
			t.Log("Packing failed")
			t.Fail()
		}
	}
	x := new(Msg)
	ns, _ := NewRR("pool.ntp.org.   390 IN  NS  a.ntpns.org")
	ns.(*NS).Ns = "a.ntpns.org"
	x.Ns = append(m.Ns, ns)
	x.Ns = append(m.Ns, ns)
	x.Ns = append(m.Ns, ns)
	// This crashes due to the fact the a.ntpns.org isn't a FQDN
	// How to recover() from a remove panic()?
	if _, err := x.Pack(); err == nil {
		t.Log("Packing should fail")
		t.Fail()
	}
	x.Answer = make([]RR, 1)
	x.Answer[0], err = NewRR(rr[0])
	if _, err := x.Pack(); err == nil {
		t.Log("Packing should fail")
		t.Fail()
	}
	x.Question = make([]Question, 1)
	x.Question[0] = Question{";sd#eddddséâèµâââ¥âxzztsestxssweewwsssstx@s@Zåµe@cn.pool.ntp.org.", TypeA, ClassINET}
	if _, err := x.Pack(); err == nil {
		t.Log("Packing should fail")
		t.Fail()
	}
}

func TestCompressLength(t *testing.T) {
	m := new(Msg)
	m.SetQuestion("miek.nl", TypeMX)
	ul := m.Len()
	m.Compress = true
	if ul != m.Len() {
		t.Fatalf("Should be equal")
	}
}

// Does the predicted length match final packed length
func TestMsgLenTest(t *testing.T) {
	var (
		// util function to build messages
		makeMsg = func(question string, ans, ns, e []RR) *Msg {
			var msg Msg
			msg.SetQuestion(Fqdn(question), TypeANY)
			msg.Answer = append(msg.Answer, ans...)
			msg.Ns = append(msg.Ns, ns...)
			msg.Extra = append(msg.Extra, e...)
			msg.Compress = true
			return &msg
		}

		name     = "12345678901234567890123456789012345.12345678.123."
		rrA, _   = NewRR(name + " 3600 IN A 192.0.2.1")
		rrMx, _  = NewRR(name + " 3600 IN MX 10 " + name)
		rrTxt, _ = NewRR(name + ` 3600 IN TXT "I am a TXT"`)
		tests    = []*Msg{
			makeMsg(name, nil, nil, nil),
			makeMsg(name, []RR{rrA}, nil, nil),
			makeMsg(name, []RR{rrMx}, nil, nil),
			makeMsg(name, []RR{rrTxt}, nil, nil),
			makeMsg(name, []RR{rrA, rrA}, nil, nil),
			makeMsg(name, []RR{rrMx, rrMx}, nil, nil),
			makeMsg(name, []RR{rrTxt, rrTxt}, nil, nil),
			makeMsg(name, []RR{rrA}, []RR{rrA}, nil),
			makeMsg(name, []RR{rrMx}, []RR{rrMx}, nil),
			makeMsg(name, []RR{rrTxt}, []RR{rrTxt}, nil),
			makeMsg(name, []RR{rrA, rrMx, rrTxt}, []RR{rrA, rrMx, rrTxt}, nil),
			makeMsg(name, []RR{rrA, rrMx, rrTxt}, []RR{rrA, rrMx, rrTxt}, []RR{rrA, rrMx, rrTxt})}
	)

	for _, msg := range tests {
		var (
			predicted = msg.Len()
			buf, err  = msg.Pack()
			actual    = len(buf)
		)
		if err != nil {
			t.Error(err)
			t.Fail()
		}
		if predicted != actual {
			t.Errorf("Predicted length is wrong: predicted %d, actual %d\n%s", predicted, actual, msg)
			t.Fail()
		}
	}
}

func TestToRFC3597(t *testing.T) {
	a, _ := NewRR("miek.nl. IN A 10.0.1.1")
	x := new(RFC3597)
	x.ToRFC3597(a)
	if x.String() != `miek.nl.	3600	IN	A	\# 4 0a000101` {
		t.Fail()
	}
}
