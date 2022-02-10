package dns

import (
	"crypto"
	"testing"
	"time"
)

func TestSIG0(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	m := new(Msg)
	m.SetQuestion("example.org.", TypeSOA)
	for _, alg := range []uint8{ECDSAP256SHA256, ECDSAP384SHA384, RSASHA1, RSASHA256, RSASHA512, ED25519} {
		algstr := AlgorithmToString[alg]
		keyrr := new(KEY)
		keyrr.Hdr.Name = algstr + "."
		keyrr.Hdr.Rrtype = TypeKEY
		keyrr.Hdr.Class = ClassINET
		keyrr.Algorithm = alg
		keysize := 512
		switch alg {
		case ECDSAP256SHA256, ED25519:
			keysize = 256
		case ECDSAP384SHA384:
			keysize = 384
		case RSASHA512:
			keysize = 1024
		}
		pk, err := keyrr.Generate(keysize)
		if err != nil {
			t.Errorf("failed to generate key for %q: %v", algstr, err)
			continue
		}
		now := uint32(time.Now().Unix())
		sigrr := new(SIG)
		sigrr.Hdr.Name = "."
		sigrr.Hdr.Rrtype = TypeSIG
		sigrr.Hdr.Class = ClassANY
		sigrr.Algorithm = alg
		sigrr.Expiration = now + 300
		sigrr.Inception = now - 300
		sigrr.KeyTag = keyrr.KeyTag()
		sigrr.SignerName = keyrr.Hdr.Name
		mb, err := sigrr.Sign(pk.(crypto.Signer), m)
		if err != nil {
			t.Errorf("failed to sign message using %q: %v", algstr, err)
			continue
		}
		m := new(Msg)
		if err := m.Unpack(mb); err != nil {
			t.Errorf("failed to unpack message signed using %q: %v", algstr, err)
			continue
		}
		if len(m.Extra) != 1 {
			t.Errorf("missing SIG for message signed using %q", algstr)
			continue
		}
		var sigrrwire *SIG
		switch rr := m.Extra[0].(type) {
		case *SIG:
			sigrrwire = rr
		default:
			t.Errorf("expected SIG RR, instead: %v", rr)
			continue
		}
		for _, rr := range []*SIG{sigrr, sigrrwire} {
			id := "sigrr"
			if rr == sigrrwire {
				id = "sigrrwire"
			}
			if err := rr.Verify(keyrr, mb); err != nil {
				t.Errorf("failed to verify %q signed SIG(%s): %v", algstr, id, err)
				continue
			}
		}
		mb[13]++
		if err := sigrr.Verify(keyrr, mb); err == nil {
			t.Errorf("verify succeeded on an altered message using %q", algstr)
			continue
		}
		sigrr.Expiration = 2
		sigrr.Inception = 1
		mb, _ = sigrr.Sign(pk.(crypto.Signer), m)
		if err := sigrr.Verify(keyrr, mb); err == nil {
			t.Errorf("verify succeeded on an expired message using %q", algstr)
			continue
		}
	}
}
