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
	PackDomainName("aa\\.bb.nl.", buf, 0, nil)
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

func TestParseZone(t *testing.T) {
	zone := `z1.miek.nl. 86400 IN RRSIG NSEC 8 3 86400 20110823011301 20110724011301 12051 miek.nl. lyRljEQFOmajcdo6bBI67DsTlQTGU3ag9vlE07u7ynqt9aYBXyE9mkasAK4V0oI32YGb2pOSB6RbbdHwUmSt+cYhOA49tl2t0Qoi3pH21dicJiupdZuyjfqUEqJlQoEhNXGtP/pRvWjNA4pQeOsOAoWq/BDcWCSQB9mh2LvUOH4= ; {keyid = sksak}
z2.miek.nl.  86400   IN      NSEC    miek.nl. TXT RRSIG NSEC
$TTL 100
z3.miek.nl.  IN      NSEC    miek.nl. TXT RRSIG NSEC`
	// Need to implementen owner substitution in the lexer.
        to := ParseZone(strings.NewReader(zone))
	i := 0
	for x := range to {
		if x.Error == nil {
			switch i {
			case 0:
				if x.Rr.Header().Name != "z1.miek.nl." {
					t.Log("Failed to parse z1")
					t.Fail()
				}
			case 1:
				if x.Rr.Header().Name != "z2.miek.nl." {
					t.Log("Failed to parse z2")
					t.Fail()
				}
			case 2:
                                if x.Rr.String() != "z3.miek.nl.\t100\tIN\tNSEC\tmiek.nl. TXT RRSIG NSEC" {
					t.Logf("Failed to parse z3 %s", x.Rr.String())
					t.Fail()
                                }
			}
		} else {
			t.Logf("Failed to parse: %v\n", x.Error)
			t.Fail()
		}
		i++
	}
}

func TestDomainName(t *testing.T) {
        tests := []string{"r\\.gieben.miek.nl.", "www\\.www.miek.nl."}
        dbuff := make([]byte, 40)


        for _, ts := range tests {
                if _, ok := PackDomainName(ts, dbuff, 0, nil); !ok {
                        t.Log("Not a valid domain name")
                        t.Fail()
                        continue
                }
                n, _, ok := UnpackDomainName(dbuff, 0)
                if !ok {
                        t.Log("Failed to unpack packed domain name")
                        t.Fail()
                        continue;
                }
                if ts != n {
                        t.Logf("Must be equal: in: %s, out: %s\n", ts, n)
                        t.Fail()
                }
        }
}

func TestParseBrace(t *testing.T) {
	tests := map[string]string{
		"(miek.nl.) 3600 IN A 127.0.0.1":                 "miek.nl.\t3600\tIN\tA\t127.0.0.1",
		"miek.nl. (3600) IN MX (10) elektron.atoom.net.": "miek.nl.\t3600\tIN\tMX\t10 elektron.atoom.net.",
		`miek.nl. IN (
                        3600 A 127.0.0.1)`: "miek.nl.\t3600\tIN\tA\t127.0.0.1",
		"(miek.nl.) (A) (127.0.0.1)": "miek.nl.\t3600\tIN\tA\t127.0.0.1",
		"miek.nl A 127.0.0.1": "miek.nl.\t3600\tIN\tA\t127.0.0.1",
		"miek.nl. NS ns.miek.nl": "miek.nl.\t3600\tIN\tNS\tns.miek.nl.",
		`(miek.nl.) (
                        (IN) 
                        (AAAA)
                        (::1) )`: "miek.nl.\t3600\tIN\tAAAA\t::1",
		`(miek.nl.) (
                        (IN) 
                        (AAAA)
                        (::1))`: "miek.nl.\t3600\tIN\tAAAA\t::1",
                "miek\\.nl. IN A 127.0.0.1": "miek\\.nl.\t3600\tIN\tA\t127.0.0.1",
		"miek.nl. IN A 127.0.0.1": "miek.nl.\t3600\tIN\tA\t127.0.0.1",
		`miek.nl.       86400 IN SOA elektron.atoom.net. miekg.atoom.net. (
                                2009032802 ; serial
                                21600      ; refresh (6 hours)
                                7200       ; retry (2 hours)
                                604800     ; expire (1 week)
                                3600       ; minimum (1 hour)
                        )`: "miek.nl.\t86400\tIN\tSOA\telektron.atoom.net. miekg.atoom.net. 2009032802 21600 7200 604800 3600",
	}
	for i, o := range tests {
		rr, e := NewRR(i)
		if e != nil {
			t.Log("Failed to parse RR: " + e.Error())
			t.Fail()
			continue
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
		"miek.nl. ) IN MX 10 miek.nl.",
	}

	for _, s := range tests {
		_, err := NewRR(s)
		if err == nil {
			t.Log("Should have triggered an error")
			t.Fail()
		}
	}
}

// A bit useless, how to use b.N?
func BenchmarkZoneParsing(b *testing.B) {
	f, err := os.Open("miek.nl.signed_test")
	if err != nil {
		return
	}
	defer f.Close()
        to := ParseZone(f)
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
	start := time.Now().UnixNano()
        to := ParseZone(f)
	var i int
	for x := range to {
		t.Logf("%s\n", x.Rr)
		i++
	}
	delta := time.Now().UnixNano() - start
	t.Logf("%d RRs parsed in %.2f s (%.2f RR/s)", i, float32(delta)/1e9, float32(i)/(float32(delta)/1e9))
}

/*
func TestZoneParsingBigZonePrint(t *testing.T) {
	f, err := os.Open("test.zone.miek.nl.signed")
	if err != nil {
		return
	}
	defer f.Close()
	start := time.Now().UnixNano()
        to := ParseZone(f)
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
	start := time.Now().UnixNano()
        to := ParseZone(f)
	var i int
	for x := range to {
		x = x
		i++
	}
	delta := time.Now().UnixNano() - start
	t.Logf("%d RRs parsed in %.2f s (%.2f RR/s)", i, float32(delta)/1e9, float32(i)/(float32(delta)/1e9))
}
*/

/*
func TestLexerBrace(t *testing.T) {
	f, err := os.Open("/home/miekg/src/tmp/small")
	if err != nil {
		return
	}
	defer f.Close()
        var s scanner.Scanner
        c := make(chan lex)
        s.Init(f)
        s.Mode = 0
        s.Whitespace = 0
        go zlexer(s, c)
        for l := range c {
                if l.err != "" {
                        t.Logf("E: %s\n", l.err)
                        continue
                }
                t.Logf("%s ", l)
        }
}
*/
