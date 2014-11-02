package dns

import (
	"testing"
	"time"
)

func TestSIG0(t *testing.T) {
	keys := []struct {
		alg uint8
		rr  *KEY
		pk  PrivateKey
	}{{alg: DSA}, {alg: ECDSAP256SHA256}, {alg: ECDSAP384SHA384}, {alg: RSASHA1}, {alg: RSASHA256}, {alg: RSASHA512}}
	for i := range keys {
		keys[i].rr = new(KEY)
		keys[i].rr.Hdr.Name = AlgorithmToString[keys[i].alg] + "."
		keys[i].rr.Hdr.Rrtype = TypeKEY
		keys[i].rr.Hdr.Class = ClassINET
		keys[i].rr.Algorithm = keys[i].alg
		keysize := 1024
		switch keys[i].alg {
		case ECDSAP256SHA256:
			keysize = 256
		case ECDSAP384SHA384:
			keysize = 384
		}
		pk, err := keys[i].rr.Generate(keysize)
		if err != nil {
			t.Logf("Failed to generate key for “%s”: %v", AlgorithmToString[keys[i].alg], err)
			t.Fail()
			continue
		}
		keys[i].pk = pk
	}

	m := new(Msg)
	m.SetQuestion("example.org.", TypeSOA)
	for _, key := range keys {
		if key.pk == nil {
			continue
		}
		algstr := AlgorithmToString[key.alg]
		now := uint32(time.Now().Unix())
		sigrr := new(SIG)
		sigrr.Hdr.Name = "."
		sigrr.Hdr.Rrtype = TypeSIG
		sigrr.Hdr.Class = ClassANY
		sigrr.Algorithm = key.rr.Algorithm
		sigrr.Expiration = now + 300
		sigrr.Inception = now - 300
		sigrr.KeyTag = key.rr.KeyTag()
		sigrr.SignerName = key.rr.Hdr.Name
		mb, err := sigrr.Sign(key.pk, m)
		if err != nil {
			t.Logf("Failed to sign message using “%s”: %v", algstr, err)
			t.Fail()
			continue
		}
		m := new(Msg)
		if err := m.Unpack(mb); err != nil {
			t.Logf("Failed to unpack message signed using “%s”: %v", algstr, err)
			t.Fail()
			continue
		}
		if len(m.Extra) != 1 {
			t.Logf("Missing SIG for message signed using “%s”", algstr)
			t.Fail()
			continue
		}
		var sigrrwire *SIG
		switch rr := m.Extra[0].(type) {
		case *SIG:
			sigrrwire = rr
		default:
			t.Logf("Expected SIG RR, instead: %v", rr)
			t.Fail()
			continue
		}
		for _, rr := range []*SIG{sigrr, sigrrwire} {
			id := "sigrr"
			if rr == sigrrwire {
				id = "sigrrwire"
			}
			if err := rr.Verify(key.rr, mb); err != nil {
				t.Logf("Failed to verify “%s” signed SIG(%s): %v", algstr, id, err)
				t.Fail()
				continue
			}
		}
		mb[13]++
		if err := sigrr.Verify(key.rr, mb); err == nil {
			t.Logf("Verify succeeded on an altered message using “%s”", algstr)
			t.Fail()
			continue
		}
		sigrr.Expiration = 2
		sigrr.Inception = 1
		mb, _ = sigrr.Sign(key.pk, m)
		if err := sigrr.Verify(key.rr, mb); err == nil {
			t.Logf("Verify succeeded on an expired message using “%s”", algstr)
			t.Fail()
			continue
		}
	}
}
