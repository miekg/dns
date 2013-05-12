// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"strings"
	"testing"
)

func getKey() *DNSKEY {
	key := new(DNSKEY)
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSASHA256
	key.PublicKey = "AwEAAcNEU67LJI5GEgF9QLNqLO1SMq1EdoQ6E9f85ha0k0ewQGCblyW2836GiVsm6k8Kr5ECIoMJ6fZWf3CQSQ9ycWfTyOHfmI3eQ/1Covhb2y4bAmL/07PhrL7ozWBW3wBfM335Ft9xjtXHPy7ztCbV9qZ4TVDTW/Iyg0PiwgoXVesz"
	return key
}

func getSoa() *SOA {
	soa := new(SOA)
	soa.Hdr = RR_Header{"miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400
	return soa
}

func TestGenerateEC(t *testing.T) {
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = ECDSAP256SHA256
	privkey, _ := key.Generate(256)
	t.Logf("%s\n", key.String())
	t.Logf("%s\n", key.PrivateKeyString(privkey))
}

func TestGenerateDSA(t *testing.T) {
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = DSA
	privkey, _ := key.Generate(1024)
	t.Logf("%s\n", key.String())
	t.Logf("%s\n", key.PrivateKeyString(privkey))
}

func TestGenerateRSA(t *testing.T) {
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSASHA256
	privkey, _ := key.Generate(1024)
	t.Logf("%s\n", key.String())
	t.Logf("%s\n", key.PrivateKeyString(privkey))
}

func TestSecure(t *testing.T) {
	soa := getSoa()

	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = TypeSOA
	sig.Algorithm = RSASHA256
	sig.Labels = 2
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.OrigTtl = 14400
	sig.KeyTag = 12051
	sig.SignerName = "miek.nl."
	sig.Signature = "oMCbslaAVIp/8kVtLSms3tDABpcPRUgHLrOR48OOplkYo+8TeEGWwkSwaz/MRo2fB4FxW0qj/hTlIjUGuACSd+b1wKdH5GvzRJc2pFmxtCbm55ygAh4EUL0F6U5cKtGJGSXxxg6UFCQ0doJCmiGFa78LolaUOXImJrk6AFrGa0M="

	key := new(DNSKEY)
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSASHA256
	key.PublicKey = "AwEAAcNEU67LJI5GEgF9QLNqLO1SMq1EdoQ6E9f85ha0k0ewQGCblyW2836GiVsm6k8Kr5ECIoMJ6fZWf3CQSQ9ycWfTyOHfmI3eQ/1Covhb2y4bAmL/07PhrL7ozWBW3wBfM335Ft9xjtXHPy7ztCbV9qZ4TVDTW/Iyg0PiwgoXVesz"

	// It should validate. Period is checked seperately, so this will keep on working
	if sig.Verify(key, []RR{soa}) != nil {
		t.Log("Failure to validate")
		t.Fail()
	}
}

func TestSignature(t *testing.T) {
	sig := new(RRSIG)
	sig.Hdr.Name = "miek.nl."
	sig.Hdr.Class = ClassINET
	sig.Hdr.Ttl = 3600
	sig.TypeCovered = TypeDNSKEY
	sig.Algorithm = RSASHA1
	sig.Labels = 2
	sig.OrigTtl = 4000
	sig.Expiration = 1000 //Thu Jan  1 02:06:40 CET 1970
	sig.Inception = 800   //Thu Jan  1 01:13:20 CET 1970
	sig.KeyTag = 34641
	sig.SignerName = "miek.nl."
	sig.Signature = "AwEAAaHIwpx3w4VHKi6i1LHnTaWeHCL154Jug0Rtc9ji5qwPXpBo6A5sRv7cSsPQKPIwxLpyCrbJ4mr2L0EPOdvP6z6YfljK2ZmTbogU9aSU2fiq/4wjxbdkLyoDVgtO+JsxNN4bjr4WcWhsmk1Hg93FV9ZpkWb0Tbad8DFqNDzr//kZ"

	// Should not be valid
	if sig.ValidityPeriod() {
		t.Log("Should not be valid")
		t.Fail()
	}

	sig.Inception = 315565800   //Tue Jan  1 10:10:00 CET 1980
	sig.Expiration = 4102477800 //Fri Jan  1 10:10:00 CET 2100
	if !sig.ValidityPeriod() {
		t.Log("Should be valid")
		t.Fail()
	}
}

func TestSignVerify(t *testing.T) {
	// The record we want to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	soa1 := new(SOA)
	soa1.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa1.Ns = "open.nlnetlabs.nl."
	soa1.Mbox = "miekg.atoom.net."
	soa1.Serial = 1293945905
	soa1.Refresh = 14400
	soa1.Retry = 3600
	soa1.Expire = 604800
	soa1.Minttl = 86400

	// With this key
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSASHA256
	privkey, _ := key.Generate(512)

	// Fill in the values of the Sig, before signing
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels, _, _ = IsDomainName(soa.Hdr.Name)
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = RSASHA256

	for _, r := range []RR{soa, soa1} {
		if sig.Sign(privkey, []RR{r}) != nil {
			t.Log("Failure to sign the SOA record")
			t.Fail()
			continue
		}
		if sig.Verify(key, []RR{r}) != nil {
			t.Log("Failure to validate")
			t.Fail()
			continue
		}
		t.Logf("Validated: %s\n", r.Header().Name)
	}
}

func TestDnskey(t *testing.T) {
	//	f, _ := os.Open("t/Kmiek.nl.+010+05240.key")
	pubkey, _ := ReadRR(strings.NewReader(`
miek.nl.	IN	DNSKEY	256 3 10 AwEAAZuMCu2FdugHkTrXYgl5qixvcDw1aDDlvL46/xJKbHBAHY16fNUb2b65cwko2Js/aJxUYJbZk5dwCDZxYfrfbZVtDPQuc3o8QaChVxC7/JYz2AHc9qHvqQ1j4VrH71RWINlQo6VYjzN/BGpMhOZoZOEwzp1HfsOE3lNYcoWU1smL ;{id = 5240 (zsk), size = 1024b}
`), "Kmiek.nl.+010+05240.key")
	privkey, _ := pubkey.(*DNSKEY).ReadPrivateKey(strings.NewReader(`
Private-key-format: v1.2
Algorithm: 10 (RSASHA512)
Modulus: m4wK7YV26AeROtdiCXmqLG9wPDVoMOW8vjr/EkpscEAdjXp81RvZvrlzCSjYmz9onFRgltmTl3AINnFh+t9tlW0M9C5zejxBoKFXELv8ljPYAdz2oe+pDWPhWsfvVFYg2VCjpViPM38EakyE5mhk4TDOnUd+w4TeU1hyhZTWyYs=
PublicExponent: AQAB
PrivateExponent: UfCoIQ/Z38l8vB6SSqOI/feGjHEl/fxIPX4euKf0D/32k30fHbSaNFrFOuIFmWMB3LimWVEs6u3dpbB9CQeCVg7hwU5puG7OtuiZJgDAhNeOnxvo5btp4XzPZrJSxR4WNQnwIiYWbl0aFlL1VGgHC/3By89ENZyWaZcMLW4KGWE=
Prime1: yxwC6ogAu8aVcDx2wg1V0b5M5P6jP8qkRFVMxWNTw60Vkn+ECvw6YAZZBHZPaMyRYZLzPgUlyYRd0cjupy4+fQ==
Prime2: xA1bF8M0RTIQ6+A11AoVG6GIR/aPGg5sogRkIZ7ID/sF6g9HMVU/CM2TqVEBJLRPp73cv6ZeC3bcqOCqZhz+pw==
Exponent1: xzkblyZ96bGYxTVZm2/vHMOXswod4KWIyMoOepK6B/ZPcZoIT6omLCgtypWtwHLfqyCz3MK51Nc0G2EGzg8rFQ==
Exponent2: Pu5+mCEb7T5F+kFNZhQadHUklt0JUHbi3hsEvVoHpEGSw3BGDQrtIflDde0/rbWHgDPM4WQY+hscd8UuTXrvLw==
Coefficient: UuRoNqe7YHnKmQzE6iDWKTMIWTuoqqrFAmXPmKQnC+Y+BQzOVEHUo9bXdDnoI9hzXP1gf8zENMYwYLeWpuYlFQ==
`), "Kmiek.nl.+010+05240.private")
	if pubkey.(*DNSKEY).PublicKey != "AwEAAZuMCu2FdugHkTrXYgl5qixvcDw1aDDlvL46/xJKbHBAHY16fNUb2b65cwko2Js/aJxUYJbZk5dwCDZxYfrfbZVtDPQuc3o8QaChVxC7/JYz2AHc9qHvqQ1j4VrH71RWINlQo6VYjzN/BGpMhOZoZOEwzp1HfsOE3lNYcoWU1smL" {
		t.Log("Pubkey is not what we've read")
		t.Fail()
	}
	// Coefficient looks fishy...
	t.Logf("%s", pubkey.(*DNSKEY).PrivateKeyString(privkey))
}

/*
        return
	// This key was generate with LDNS:
	// ldns-keygen -a RSASHA256 -r /dev/urandom -b 1024 miek.nl
	// Show that we have al the RSA parameters and can check them
	// here to see what I came up with
	key := new(RR_DNSKEY)
	key.Hdr.Name = "miek.nl."
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 3600
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSASHA256
	key.PublicKey = "AwEAAcELcuxHosJX3LjbR6EFzsqI3mKivwvO6Y5Kzt/OXYmLQUI8tnOrX9ilT/0qGraxoONayVX3A6bl1pG3h/xOxVEGcJGqbrZnhr2+4S9tW2GWQwevV+NhinE7v6MCCCheVCnAPh0KFb/u14ng3DQizP1spBU/NoAN31l678snBpZX"

	soa := new(RR_SOA)
	soa.Hdr = RR_Header{"Miek.nl.", TypeSOA, ClassINET, 875, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293513905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	sig := new(RR_RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = TypeSOA
	sig.Algorithm = RSASHA256
	sig.Labels = 2
	sig.Expiration = 1296098705 // date '+%s' -d"2011-01-27 04:25:05
	sig.Inception = 1293506705
	sig.OrigTtl = 14400
	//sig.KeyTag = 12051
	sig.KeyTag = 12273 //faked
	sig.SignerName = "miek.nl."
	sig.Signature = "kLq/5oFy3Sh5ZxPGFMCyHq8MtN6E17R1Ln9+bJ2Q76YYAxFE8Xlie33A1GFctH2uhzRzJKuP/JSjUkrvGk2rjBm32z9zXtZsKx/4yV0da2nLRm44NOmX6gsP4Yia8mdqPUajjkyLzAzU2bevtesJm0Z65AcmPdq3tUZODdRAcng="

	sig.Verify(key, []RR{soa})

	// From Kmiek.nl*.private
        openssl := "135560614087352210480379313279722604826647214111257577861451621491284835543707521986085999189597017237768514876957888744370440811423088511394629855684615382349190289731989185193184712980579812986523080792122141528583964882610028199770199112837017606561901919812183422914622295620927795008308854924436086101591"
        println("OPENSSL key: what should be is: ",openssl)
}
*/

func TestTag(t *testing.T) {
	key := new(DNSKEY)
	key.Hdr.Name = "miek.nl."
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 3600
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSASHA256
	key.PublicKey = "AwEAAcNEU67LJI5GEgF9QLNqLO1SMq1EdoQ6E9f85ha0k0ewQGCblyW2836GiVsm6k8Kr5ECIoMJ6fZWf3CQSQ9ycWfTyOHfmI3eQ/1Covhb2y4bAmL/07PhrL7ozWBW3wBfM335Ft9xjtXHPy7ztCbV9qZ4TVDTW/Iyg0PiwgoXVesz"

	tag := key.KeyTag()
	if tag != 12051 {
		t.Logf("Wrong key tag: %d for key %v\n", tag, key)
		t.Fail()
	}
}

func TestKeyRSA(t *testing.T) {
	key := new(DNSKEY)
	key.Hdr.Name = "miek.nl."
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 3600
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSASHA256
	priv, _ := key.Generate(2048)

	soa := new(SOA)
	soa.Hdr = RR_Header{"miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = TypeSOA
	sig.Algorithm = RSASHA256
	sig.Labels = 2
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.OrigTtl = soa.Hdr.Ttl
	sig.KeyTag = key.KeyTag()
	sig.SignerName = key.Hdr.Name

	if err := sig.Sign(priv, []RR{soa}); err != nil {
		t.Logf("Failed to sign")
		t.Fail()
		return
	}
	if err := sig.Verify(key, []RR{soa}); err != nil {
		t.Logf("Failed to verify")
		t.Fail()
	}
}

func TestKeyToDS(t *testing.T) {
	key := new(DNSKEY)
	key.Hdr.Name = "miek.nl."
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 3600
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSASHA256
	key.PublicKey = "AwEAAcNEU67LJI5GEgF9QLNqLO1SMq1EdoQ6E9f85ha0k0ewQGCblyW2836GiVsm6k8Kr5ECIoMJ6fZWf3CQSQ9ycWfTyOHfmI3eQ/1Covhb2y4bAmL/07PhrL7ozWBW3wBfM335Ft9xjtXHPy7ztCbV9qZ4TVDTW/Iyg0PiwgoXVesz"

	ds := key.ToDS(SHA1)
	if strings.ToUpper(ds.Digest) != "B5121BDB5B8D86D0CC5FFAFBAAABE26C3E20BAC1" {
		t.Logf("Wrong DS digest for SHA1\n%v\n", ds)
		t.Fail()
	}
}
