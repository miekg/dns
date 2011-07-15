package dns

import (
	"fmt"
	"net"
        "strings"
	"testing"
	"crypto/rsa"
)

func TestPrivateKeyRead1(t *testing.T) {
	a := `Private-key-format: v1.3
Algorithm: 5 (RSASHA1)
Modulus: vyVjCzz87g3rg9vDj1NJ1tlFP7lEY2pEQLkWGXAFuZM6Fw/bNmEH/z3ybDfsJqx4QQ6YZXN8V2kbzY7oX+tExf6AMiMIcKYzEGwg5xBYFh33du4G+6kE/VzG906ubpaIEnrZOMTdGqE7OwptAqrqXe4uGXY99ZqNdqutOKQyIzs=
PublicExponent: AQAB
PrivateExponent: PFg/RoMAjt8SJVSyDoOK4itBs3Z34rLfzVchZPJ6vDWAt1soJ6jGb4xNBmE5SpRUeqVy80RcUvQ59NFTB0UtNo/zAXhC1RfKiFCNRFTyV3k6a9CMLPAU9g4peW91lw87HXnYALTC9bTiTAoMU3vKvNx80F5qfK7qY/N28S1PMeE=
Prime1: +vPWyp37iUa7/LbhejOX/KdkhfwECUCdJF0uEePjaBCSf85xceEBzU89JFk9dCojtVqcI8xLKnRKRixg07Rc+Q==
Prime2: wv2aVWr13Cq2vRkKiHlqqP9vihGuDN/kWfmXb7slJH3s2i9+yI7vepAlow9SY8lNHOqXibEaAFsP3aj5OAAS0w==
Exponent1: sChCenBzhWV1yGvH0zQsWFpYogTKAISuyjvufvhtRTt82uJbmAjObwRUcxOBo+2Aq2kzeZ2Klf6TtLaqMXHGYQ==
Exponent2: hXiKeAWrHXWveGj3qMtTkzKl6uCHPxDSgjQy0KxNlFkOE5uHMUmF62NYH/GQ9/UG79A0wm+T2MJ8bcIINaj3OQ==
Coefficient: xzZBvs2/IT7+iRQdn9I4slRTg9ryIecx7oKEKYTOEeyL2qq7rfY/FwZGy3EqyA/3lrkfFLx76qOeqAmCTUaU4w==
Created: 20101221142359
Publish: 20101221142359
Activate: 20101221142359`

	k := new(RR_DNSKEY)
	p, _ := k.ReadPrivateKey(strings.NewReader(a))
	p = p
}

func TestPrivateKeyRead2(t *testing.T) {
	/*        b:=`; This is a zone-signing key, keyid 41946, for miek.nl.
	; Created: 20110109154937 (Sun Jan  9 16:49:37 2011)
	; Publish: 20110109154937 (Sun Jan  9 16:49:37 2011)
	; Activate: 20110109154937 (Sun Jan  9 16:49:37 2011)
	miek.nl. IN DNSKEY 256 3 5 AwEAAeETsGZdYlTsHK8wc1yo9Zcj4dMEpPWRTYuTmGD3e4Qsk4/uyKf5jhsNZhp8no7GKHTEe7+K1prC4iXo3X5oQyDDmx76hDo5u6fblu/XaQw16wqMDQDPiURUKkzobJlmY6fYNKRz7A01J73V6qDMCvlk+8p+fb0a+LiJ2NJDACln`
	*/

	a := `Private-key-format: v1.3
Algorithm: 5 (RSASHA1)
Modulus: 4ROwZl1iVOwcrzBzXKj1lyPh0wSk9ZFNi5OYYPd7hCyTj+7Ip/mOGw1mGnyejsYodMR7v4rWmsLiJejdfmhDIMObHvqEOjm7p9uW79dpDDXrCowNAM+JRFQqTOhsmWZjp9g0pHPsDTUnvdXqoMwK+WT7yn59vRr4uInY0kMAKWc=
PublicExponent: AQAB
PrivateExponent: CYYAv8QRxhAbgpolN3V6tsNw6bHXnQBh7Jb5KpkuI8CTGdL7sIfRqHlfqZ0+REJEMfSiW89vFytJ0FrTDGcy99qesJujW/tlfsThRTwFSXdCNv0Df25CNNNeskMg3r86is8MmHJc+dAjN3P0ArAF2yZd9gS7C4TGKDDR3bZ9SYk=
Prime1: 8EO3P0cYdR8FISxLaUVfVJVIVAWux7tptnqZlzAmomPGEipXr2bAYf637hAAoD8xEUXbI6FIkXUk5vIjxfUjRQ==
Prime2: 79FWWF5PNh6ykof9NsrR2YRy/P30iLbzfSRVQrrYH15SEip5LUN15W/G7bg5Uyp8U/o3HXaaxhrj9LC330Uuuw==
Exponent1: mtOIKoauBAtRSuc4UUYbAG6ShVKEJsFmhejLQNoOi2awJNSUXLtiDcQO0qINRTZzcCYL6RHtqY5LkWdIFjC54Q==
Exponent2: ZpsiXly7d2Ra8ubMKA1PC8nniOb/IR9lvj01XX+jyIgKhUs23W7nmmrgqgUQQc0DtMpxmmGMhwYqUh7qDNUE0Q==
Coefficient: 2wn6uW28qM6B68m1ADcLmzjwIQn9Xyc/JMydrJUSzwG7Fr08bc1aa1+K/K0pVy82vU5emDKdVXPP4+WtqXnUNA==
Created: 20110109154937
Publish: 20110109154937
Activate: 20110109154937`

	k := new(RR_DNSKEY)
	k.Hdr.Rrtype = TypeDNSKEY
	k.Hdr.Class = ClassINET
	k.Hdr.Name = "miek.nl."
	k.Hdr.Ttl = 3600
	k.Protocol = 3
	k.Flags = 256
        k.Algorithm = RSASHA1
	p, _ := k.ReadPrivateKey(strings.NewReader(a))
	switch priv := p.(type) {
	case *rsa.PrivateKey:
		if 65537 != priv.PublicKey.E {
			t.Log("Exponenent should be 65537")
			t.Fail()
		}
	}
	if k.KeyTag() != 41946 {
		t.Logf("%v\n", k)
		t.Log("Keytag should be 41946")
		t.Fail()
	}

	soa := new(RR_SOA)
	soa.Hdr = RR_Header{"miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	sig := new(RR_RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = k.KeyTag()
	sig.SignerName = k.Hdr.Name
	sig.Algorithm = k.Algorithm

	sig.Sign(p, []RR{soa})
	fmt.Printf("%v\n%v\n%v\n", k, soa, sig)
}

func TestA(t *testing.T) {
	a := new(RR_A)
	a.Hdr = RR_Header{"miek.nl.", TypeA, ClassINET, 14400, 0}
	a.A = net.ParseIP("192.168.1.1")
	str := a.String()
	if str != "miek.nl.\t14400\tIN\tA\t192.168.1.1" {
		t.Log(str)
		t.Fail()
	}
}

func TestQuadA(t *testing.T) {
	a := new(RR_AAAA)
	a.Hdr = RR_Header{"miek.nl.", TypeAAAA, ClassINET, 14400, 0}
	a.AAAA = net.ParseIP("::1")
	str := a.String()
	if str != "miek.nl.\t14400\tIN\tAAAA\t::1" {
		t.Log(str)
		t.Fail()
	}
}

func TestDotInName(t *testing.T) {
	buf := make([]byte, 20)
	packDomainName("aa\\.bb.nl.", buf, 0)
        // index 3 must be a real dot
        if buf[3] != '.' {
                t.Log("Dot should be a real dot")
                t.Fail()
        }

        if buf[6] != 2 {
                t.Log("This must have the value 2")
                t.Fail()
        }
        dom, _, _ := unpackDomainName(buf, 0)
        // printing it should yield the backspace again
        if dom != "aa\\.bb.nl." {
                t.Log("Dot should have been escaped: " + dom)
                t.Fail()
        }
}

// New style (Ragel) parsing
func TestParse(t *testing.T) {
        rr, _ := Zparse("miek.nl.    3600    IN    A   127.0.0.1")
        fmt.Printf("Seen a:\n%v\n", rr)
        rr, _ = Zparse("miek.nl.     3600    IN    MX   10      elektron.atoom.net.")
        fmt.Printf("Seen a:\n%v\n", rr)
        rr, _ = Zparse("nlnetlabs.nl. 3175 IN DNSKEY  256 3 8 AwEAAdR7XR95OaAN9Rz7TbtPalQ9guQk7zfxTHYNKhsiwTZA9z+F16nD0VeBlk7dNik3ETpT2GLAwr9sntG898JwurCDe353wHPvjZtMCdiTVp3cRCrjuCEvoFpmZNN82H0gaH/4v8mkv/QBDAkDSncYjz/FqHKAeYy3cMcjY6RyVweh");
        fmt.Printf("Seen a:\n%v\n", rr)
        rr, _ = Zparse("miek.nl.    IN    A   127.0.0.1")
        fmt.Printf("Seen a:\n%v\n", rr)
        rr, _ = Zparse("miek.nl.    IN 3600   A   127.0.0.1")
        fmt.Printf("Seen a:\n%v\n", rr)
        rr, _ = Zparse("miek.nl.    A   127.0.0.1")
        fmt.Printf("Seen a:\n%v\n", rr)
}
