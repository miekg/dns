package dns

import (
	"crypto/rsa"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSign(t *testing.T) {
	pub := "miek.nl. IN DNSKEY 256 3 5 AwEAAb+8lGNCxJgLS8rYVer6EnHVuIkQDghdjdtewDzU3G5R7PbMbKVRvH2Ma7pQyYceoaqWZQirSj72euPWfPxQnMy9ucCylA+FuH9cSjIcPf4PqJfdupHk9X6EBYjxrCLY4p1/yBwgyBIRJtZtAqM3ceAH2WovEJD6rTtOuHo5AluJ"

	priv := `Private-key-format: v1.3
Algorithm: 5 (RSASHA1)
Modulus: v7yUY0LEmAtLythV6voScdW4iRAOCF2N217APNTcblHs9sxspVG8fYxrulDJhx6hqpZlCKtKPvZ649Z8/FCczL25wLKUD4W4f1xKMhw9/g+ol926keT1foQFiPGsItjinX/IHCDIEhEm1m0Cozdx4AfZai8QkPqtO064ejkCW4k=
PublicExponent: AQAB
PrivateExponent: YPwEmwjk5HuiROKU4xzHQ6l1hG8Iiha4cKRG3P5W2b66/EN/GUh07ZSf0UiYB67o257jUDVEgwCuPJz776zfApcCB4oGV+YDyEu7Hp/rL8KcSN0la0k2r9scKwxTp4BTJT23zyBFXsV/1wRDK1A5NxsHPDMYi2SoK63Enm/1ptk=
Prime1: /wjOG+fD0ybNoSRn7nQ79udGeR1b0YhUA5mNjDx/x2fxtIXzygYk0Rhx9QFfDy6LOBvz92gbNQlzCLz3DJt5hw==
Prime2: wHZsJ8OGhkp5p3mrJFZXMDc2mbYusDVTA+t+iRPdS797Tj0pjvU2HN4vTnTj8KBQp6hmnY7dLp9Y1qserySGbw==
Exponent1: N0A7FsSRIg+IAN8YPQqlawoTtG1t1OkJ+nWrurPootScApX6iMvn8fyvw3p2k51rv84efnzpWAYiC8SUaQDNxQ==
Exponent2: SvuYRaGyvo0zemE3oS+WRm2scxR8eiA8WJGeOc+obwOKCcBgeZblXzfdHGcEC1KaOcetOwNW/vwMA46lpLzJNw==
Coefficient: 8+7ZN/JgByqv0NfULiFKTjtyegUcijRuyij7yNxYbCBneDvZGxJwKNi4YYXWx743pcAj4Oi4Oh86gcmxLs+hGw==
Created: 20110302104537
Publish: 20110302104537
Activate: 20110302104537`

	xk, _ := NewRR(pub)
	k := xk.(*RR_DNSKEY)
	p, err := ReadPrivateKey(strings.NewReader(priv))
	if err != nil {
		t.Logf("%v\n", err)
		t.Fail()
	}
	switch priv := p.(type) {
	case *rsa.PrivateKey:
		if 65537 != priv.PublicKey.E {
			t.Log("Exponenent should be 65537")
			t.Fail()
		}
	default:
		t.Logf("We should have read an RSA key: %v", priv)
		t.Fail()
	}
	if k.KeyTag() != 37350 {
		t.Logf("%d %v\n", k.KeyTag(), k)
		t.Log("Keytag should be 37350")
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
	if sig.Signature != "D5zsobpQcmMmYsUMLxCVEtgAdCvTu8V/IEeP4EyLBjqPJmjt96bwM9kqihsccofA5LIJ7DN91qkCORjWSTwNhzCv7bMyr2o5vBZElrlpnRzlvsFIoAZCD9xg6ZY7ZyzUJmU6IcTwG4v3xEYajcpbJJiyaw/RqR90MuRdKPiBzSo=" {
		t.Log("Signature is not correct")
		t.Logf("%v\n", sig)
		t.Fail()
	}
}

func TestDotInName(t *testing.T) {
	buf := make([]byte, 20)
	PackDomainName("aa\\.bb.nl.", buf, 0)
	// index 3 must be a real dot
	if buf[3] != '.' {
		t.Log("Dot should be a real dot")
		t.Fail()
	}

	if buf[6] != 2 {
		t.Log("This must have the value 2")
		t.Fail()
	}
	dom, _, _ := UnpackDomainName(buf, 0)
	// printing it should yield the backspace again
	if dom != "aa\\.bb.nl." {
		t.Log("Dot should have been escaped: " + dom)
		t.Fail()
	}
}

// Make this a decend test case. For now, good enough
func TestParse(t *testing.T) {
	tests := map[string]string{
		"miek.nl. 3600 IN A 127.0.0.1":               "miek.nl.\t3600\tIN\tA\t127.0.0.1",
		"miek.nl. 3600 IN MX 10 elektron.atoom.net.": "miek.nl.\t3600\tIN\tMX\t10 elektron.atoom.net.",
		"miek.nl. IN 3600 A 127.0.0.1":               "miek.nl.\t3600\tIN\tA\t127.0.0.1",
		"miek.nl. A 127.0.0.1":                       "miek.nl.\t3600\tIN\tA\t127.0.0.1",
		"miek.nl. IN AAAA ::1":                       "miek.nl.\t3600\tIN\tAAAA\t::1",
		"miek.nl. IN A 127.0.0.1":                    "miek.nl.\t3600\tIN\tA\t127.0.0.1",
		"miek.nl. IN DNSKEY 256 3 5 AwEAAb+8lGNCxJgLS8rYVer6EnHVuIkQDghdjdtewDzU3G5R7PbMbKVRvH2Ma7pQyYceoaqWZQirSj72euPWfPxQnMy9ucCylA+FuH9cSjIcPf4PqJfdupHk9X6EBYjxrCLY4p1/yBwgyBIRJtZtAqM3ceAH2WovEJD6rTtOuHo5AluJ":           "miek.nl.\t3600\tIN\tDNSKEY\t256 3 5 AwEAAb+8lGNCxJgLS8rYVer6EnHVuIkQDghdjdtewDzU3G5R7PbMbKVRvH2Ma7pQyYceoaqWZQirSj72euPWfPxQnMy9ucCylA+FuH9cSjIcPf4PqJfdupHk9X6EBYjxrCLY4p1/yBwgyBIRJtZtAqM3ceAH2WovEJD6rTtOuHo5AluJ",
		"nlnetlabs.nl. 3175 IN DNSKEY 256 3 8 AwEAAdR7XR95OaAN9Rz7TbtPalQ9guQk7zfxTHYNKhsiwTZA9z+F16nD0VeBlk7dNik3ETpT2GLAwr9sntG898JwurCDe353wHPvjZtMCdiTVp3cRCrjuCEvoFpmZNN82H0gaH/4v8mkv/QBDAkDSncYjz/FqHKAeYy3cMcjY6RyVweh": "nlnetlabs.nl.\t3175\tIN\tDNSKEY\t256 3 8 AwEAAdR7XR95OaAN9Rz7TbtPalQ9guQk7zfxTHYNKhsiwTZA9z+F16nD0VeBlk7dNik3ETpT2GLAwr9sntG898JwurCDe353wHPvjZtMCdiTVp3cRCrjuCEvoFpmZNN82H0gaH/4v8mkv/QBDAkDSncYjz/FqHKAeYy3cMcjY6RyVweh",
		"dnsex.nl.  86400 IN SOA  elektron.atoom.net. miekg.atoom.net. 1299256910 14400 3600 604800 86400":                                                                                                                      "dnsex.nl.\t86400\tIN\tSOA\telektron.atoom.net. miekg.atoom.net. 1299256910 14400 3600 604800 86400",
		// RRSIG incep/expir fails (new time api)
				"dnsex.nl.  86400 IN RRSIG    SOA 8 2 86400 20110403154150 20110304154150 23334 dnsex.nl. QN6hwJQLEBqRVKmO2LgkuRSx9bkKIZxXlTVtHg5SaiN+8RCTckGtUXkQ vmZiBt3RdIWAjaabQYpEZHgvyjfy4Wwu/9RPDYnLt/qoyr4QKAdujchc m+fMDSbbcC7AN08i5D/dUWfNOHXjRJLY7t7AYB9DBt32LazIb0EU9QiW 5Cg=": 
		                        "dnsex.nl.\t86400\tIN\tRRSIG\tSOA 8 2 86400 20110403154150 20110304154150 23334 dnsex.nl. QN6hwJQLEBqRVKmO2LgkuRSx9bkKIZxXlTVtHg5SaiN+8RCTckGtUXkQvmZiBt3RdIWAjaabQYpEZHgvyjfy4Wwu/9RPDYnLt/qoyr4QKAdujchcm+fMDSbbcC7AN08i5D/dUWfNOHXjRJLY7t7AYB9DBt32LazIb0EU9QiW5Cg=",
	}
	for i, o := range tests {
		rr, _ := NewRR(i)
		if rr == nil {
			t.Log("Failed to parse RR")
			t.Fail()
		}
		if rr.String() != o {
			t.Logf("`%s' should be equal to\n`%s', but is     `%s'\n", i, o, rr.String())
			t.Fail()
		} else {
			t.Logf("RR is OK: `%s'", rr.String())
		}
	}
}

func TestParseFailure(t *testing.T) {
	tests := []string{"miek.nl. IN A 327.0.0.1",
		"miek.nl. IN AAAA ::x",
		"miek.nl. IN MX a0 miek.nl.",
		"miek.nl aap IN MX mx.miek.nl.",
		"miek.nl. IN CNAME ",
		"miek.nl. PA MX 10 miek.nl.",
	}

	for _, s := range tests {
		_, err := NewRR(s)
		if err == nil {
			t.Log("Should have triggered an error")
			t.Fail()
		}
	}
}

// A bit useless
func BenchmarkZoneParsing(b *testing.B) {
	f, err := os.Open("miek.nl.signed_test")
	if err != nil {
		return
	}
	defer f.Close()
	to := make(chan Token)
	go ParseZone(f, to)
	for x := range to {
		x = x
	}
}

func TestZoneParsing(t *testing.T) {
	f, err := os.Open("miek.nl.signed_test")
	if err != nil {
		return
	}
	defer f.Close()
	to := make(chan Token)
	start := time.Now().Nanosecond()
	go ParseZone(f, to)
	var i int
	for x := range to {
		t.Logf("%s\n", x.Rr)
		i++
	}
	delta := time.Now().Nanosecond() - start
	t.Logf("%d RRs parsed in %.2f s (%.2f RR/s)", i, float32(delta)/1e9, float32(i)/(float32(delta)/1e9))
}

/*
func TestZoneParsingBigZonePrint(t *testing.T) {
	f, err := os.Open("test.zone.miek.nl.signed")
	if err != nil {
		return
	}
	defer f.Close()
	to := make(chan Token)
	start := time.Now().UnixNano()
	go ParseZone(f, to)
	var i int
	for x := range to {
		if x.Rr != nil {
			println(x.Rr.String())
		}
		//		t.Logf("%s\n", x.Rr)
		i++
	}
	delta := time.Now().UnixNano() - start
	t.Logf("%d RRs parsed in %.2f s (%.2f RR/s)", i, float32(delta)/1e9, float32(i)/(float32(delta)/1e9))
}

func TestZoneParsingBigZone(t *testing.T) {
	f, err := os.Open("test.zone.miek.nl.signed")
	if err != nil {
		return
	}
	defer f.Close()
	to := make(chan Token)
	start := time.Now().UnixNano()
	go ParseZone(f, to)
	var i int
	for x := range to {
		x = x
		i++
	}
	delta := time.Now().UnixNano() - start
	t.Logf("%d RRs parsed in %.2f s (%.2f RR/s)", i, float32(delta)/1e9, float32(i)/(float32(delta)/1e9))
}
*/
