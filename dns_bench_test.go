package dns

import (
	"net"
	"testing"
)

func BenchmarkMsgLength(b *testing.B) {
	b.StopTimer()
	makeMsg := func(question string, ans, ns, e []RR) *Msg {
		msg := new(Msg)
		msg.SetQuestion(Fqdn(question), TypeANY)
		msg.Answer = append(msg.Answer, ans...)
		msg.Ns = append(msg.Ns, ns...)
		msg.Extra = append(msg.Extra, e...)
		msg.Compress = true
		return msg
	}
	name1 := "12345678901234567890123456789012345.12345678.123."
	rrMx, _ := NewRR(name1 + " 3600 IN MX 10 " + name1)
	msg := makeMsg(name1, []RR{rrMx, rrMx}, nil, nil)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		msg.Len()
	}
}

func BenchmarkMsgLengthPack(b *testing.B) {
	makeMsg := func(question string, ans, ns, e []RR) *Msg {
		msg := new(Msg)
		msg.SetQuestion(Fqdn(question), TypeANY)
		msg.Answer = append(msg.Answer, ans...)
		msg.Ns = append(msg.Ns, ns...)
		msg.Extra = append(msg.Extra, e...)
		msg.Compress = true
		return msg
	}
	name1 := "12345678901234567890123456789012345.12345678.123."
	rrMx, _ := NewRR(name1 + " 3600 IN MX 10 " + name1)
	msg := makeMsg(name1, []RR{rrMx, rrMx}, nil, nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = msg.Pack()
	}
}

func BenchmarkMsgPackBuffer(b *testing.B) {
	makeMsg := func(question string, ans, ns, e []RR) *Msg {
		msg := new(Msg)
		msg.SetQuestion(Fqdn(question), TypeANY)
		msg.Answer = append(msg.Answer, ans...)
		msg.Ns = append(msg.Ns, ns...)
		msg.Extra = append(msg.Extra, e...)
		msg.Compress = true
		return msg
	}
	name1 := "12345678901234567890123456789012345.12345678.123."
	rrMx, _ := NewRR(name1 + " 3600 IN MX 10 " + name1)
	msg := makeMsg(name1, []RR{rrMx, rrMx}, nil, nil)
	buf := make([]byte, 512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = msg.PackBuffer(buf)
	}
}

func BenchmarkMsgUnpack(b *testing.B) {
	makeMsg := func(question string, ans, ns, e []RR) *Msg {
		msg := new(Msg)
		msg.SetQuestion(Fqdn(question), TypeANY)
		msg.Answer = append(msg.Answer, ans...)
		msg.Ns = append(msg.Ns, ns...)
		msg.Extra = append(msg.Extra, e...)
		msg.Compress = true
		return msg
	}
	name1 := "12345678901234567890123456789012345.12345678.123."
	rrMx, _ := NewRR(name1 + " 3600 IN MX 10 " + name1)
	msg := makeMsg(name1, []RR{rrMx, rrMx}, nil, nil)
	msgBuf, _ := msg.Pack()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = msg.Unpack(msgBuf)
	}
}

func BenchmarkPackDomainName(b *testing.B) {
	name1 := "12345678901234567890123456789012345.12345678.123."
	buf := make([]byte, len(name1)+1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = PackDomainName(name1, buf, 0, nil, false)
	}
}

func BenchmarkUnpackDomainName(b *testing.B) {
	name1 := "12345678901234567890123456789012345.12345678.123."
	buf := make([]byte, len(name1)+1)
	_, _ = PackDomainName(name1, buf, 0, nil, false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = UnpackDomainName(buf, 0)
	}
}

func BenchmarkUnpackDomainNameUnprintable(b *testing.B) {
	name1 := "\x02\x02\x02\x025\x02\x02\x02\x02.12345678.123."
	buf := make([]byte, len(name1)+1)
	_, _ = PackDomainName(name1, buf, 0, nil, false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = UnpackDomainName(buf, 0)
	}
}

func BenchmarkCopy(b *testing.B) {
	b.ReportAllocs()
	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)
	rr, _ := NewRR("miek.nl. 2311 IN A 127.0.0.1")
	m.Answer = []RR{rr}
	rr, _ = NewRR("miek.nl. 2311 IN NS 127.0.0.1")
	m.Ns = []RR{rr}
	rr, _ = NewRR("miek.nl. 2311 IN A 127.0.0.1")
	m.Extra = []RR{rr}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Copy()
	}
}

func BenchmarkPackRRA(b *testing.B) {
	a := &A{Hdr: RR_Header{Name: ".", Rrtype: TypeA, Class: ClassANY}, A: net.IPv4(127, 0, 0, 1)}

	buf := make([]byte, a.len())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = PackRR(a, buf, 0, nil, false)
	}
}

func BenchmarkUnpackRRA(b *testing.B) {
	a := &A{Hdr: RR_Header{Name: ".", Rrtype: TypeA, Class: ClassANY}, A: net.IPv4(127, 0, 0, 1)}

	buf := make([]byte, a.len())
	PackRR(a, buf, 0, nil, false)
	a = nil
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = UnpackRR(buf, 0)
	}
}
