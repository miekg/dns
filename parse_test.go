// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"crypto/rsa"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSignRSA(t *testing.T) {
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
	k := xk.(*DNSKEY)
	p, err := k.NewPrivateKey(priv)
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

func TestSignECDSA(t *testing.T) {
	pub := `example.net. 3600 IN DNSKEY 257 3 14 (
	xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1
	w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8
	/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40 )`
	priv := `Private-key-format: v1.2
Algorithm: 14 (ECDSAP384SHA384)
PrivateKey: WURgWHCcYIYUPWgeLmiPY2DJJk02vgrmTfitxgqcL4vwW7BOrbawVmVe0d9V94SR`

	eckey, err := NewRR(pub)
	if err != nil {
		t.Fatal(err.Error())
	}
	privkey, err := eckey.(*DNSKEY).NewPrivateKey(priv)
	if err != nil {
		t.Fatal(err.Error())
	}
	ds := eckey.(*DNSKEY).ToDS(SHA384)
	if ds.KeyTag != 10771 {
		t.Fatal("Wrong keytag on DS")
	}
	if ds.Digest != "72d7b62976ce06438e9c0bf319013cf801f09ecc84b8d7e9495f27e305c6a9b0563a9b5f4d288405c3008a946df983d6" {
		t.Fatal("Wrong DS Digest")
	}
	a, _ := NewRR("www.example.net. 3600 IN A 192.0.2.1")
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"example.net.", TypeRRSIG, ClassINET, 14400, 0}
	sig.Expiration, _ = StringToTime("20100909102025")
	sig.Inception, _ = StringToTime("20100812102025")
	sig.KeyTag = eckey.(*DNSKEY).KeyTag()
	sig.SignerName = eckey.(*DNSKEY).Hdr.Name
	sig.Algorithm = eckey.(*DNSKEY).Algorithm

	sig.Sign(privkey, []RR{a})

	t.Logf("%s", sig.String())
	if e := sig.Verify(eckey.(*DNSKEY), []RR{a}); e != nil {
		t.Logf("Failure to validate: %s", e.Error())
		t.Fail()
	}
}

func TestDotInName(t *testing.T) {
	buf := make([]byte, 20)
	PackDomainName("aa\\.bb.nl.", buf, 0, nil, false)
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

func TestDomainName(t *testing.T) {
	tests := []string{"r\\.gieben.miek.nl.", "www\\.www.miek.nl.",
		"www.*.miek.nl.", "www.*.miek.nl.",
	}
	dbuff := make([]byte, 40)

	for _, ts := range tests {
		if _, err := PackDomainName(ts, dbuff, 0, nil, false); err != nil {
			t.Log("Not a valid domain name")
			t.Fail()
			continue
		}
		n, _, err := UnpackDomainName(dbuff, 0)
		if err != nil {
			t.Log("Failed to unpack packed domain name")
			t.Fail()
			continue
		}
		if ts != n {
			t.Logf("Must be equal: in: %s, out: %s\n", ts, n)
			t.Fail()
		}
	}
}

func TestParseDirectiveMisc(t *testing.T) {
	tests := map[string]string{
		"$ORIGIN miek.nl.\na IN NS b": "a.miek.nl.\t3600\tIN\tNS\tb.miek.nl.",
		"$TTL 2H\nmiek.nl. IN NS b.":  "miek.nl.\t7200\tIN\tNS\tb.",
		"miek.nl. 1D IN NS b.":        "miek.nl.\t86400\tIN\tNS\tb.",
		`name. IN SOA  a6.nstld.com. hostmaster.nic.name. (
        203362132 ; serial
        5m        ; refresh (5 minutes)
        5m        ; retry (5 minutes)
        2w        ; expire (2 weeks)
        300       ; minimum (5 minutes)
)`: "name.\t3600\tIN\tSOA\ta6.nstld.com. hostmaster.nic.name. 203362132 300 300 1209600 300",
		". 3600000  IN  NS ONE.MY-ROOTS.NET.":        ".\t3600000\tIN\tNS\tONE.MY-ROOTS.NET.",
		"ONE.MY-ROOTS.NET. 3600000 IN A 192.168.1.1": "ONE.MY-ROOTS.NET.\t3600000\tIN\tA\t192.168.1.1",
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

func TestParseNSEC(t *testing.T) {
	nsectests := map[string]string{
		"nl. IN NSEC3PARAM 1 0 5 30923C44C6CBBB8F":                                                                                                 "nl.\t3600\tIN\tNSEC3PARAM\t1 0 5 30923C44C6CBBB8F",
		"p2209hipbpnm681knjnu0m1febshlv4e.nl. IN NSEC3 1 1 5 30923C44C6CBBB8F P90DG1KE8QEAN0B01613LHQDG0SOJ0TA NS SOA TXT RRSIG DNSKEY NSEC3PARAM": "p2209hipbpnm681knjnu0m1febshlv4e.nl.\t3600\tIN\tNSEC3\t1 1 5 30923C44C6CBBB8F P90DG1KE8QEAN0B01613LHQDG0SOJ0TA NS SOA TXT RRSIG DNSKEY NSEC3PARAM",
		"localhost.dnssex.nl. IN NSEC www.dnssex.nl. A RRSIG NSEC":                                                                                 "localhost.dnssex.nl.\t3600\tIN\tNSEC\twww.dnssex.nl. A RRSIG NSEC",
		"localhost.dnssex.nl. IN NSEC www.dnssex.nl. A RRSIG NSEC TYPE65534":                                                                       "localhost.dnssex.nl.\t3600\tIN\tNSEC\twww.dnssex.nl. A RRSIG NSEC TYPE65534",
	}
	for i, o := range nsectests {
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

func TestParseLOC(t *testing.T) {
	lt := map[string]string{
		"SW1A2AA.find.me.uk.	LOC	51 30 12.748 N 00 07 39.611 W 0.00m 0.00m 0.00m 0.00m": "SW1A2AA.find.me.uk.\t3600\tIN\tLOC\t51 30 12.748 N 00 07 39.611 W 0.00m 0.00m 0.00m 0.00m",
		"SW1A2AA.find.me.uk.	LOC	51 0 0.0 N 00 07 39.611 W 0.00m 0.00m 0.00m 0.00m": "SW1A2AA.find.me.uk.\t3600\tIN\tLOC\t51 00 0.000 N 00 07 39.611 W 0.00m 0.00m 0.00m 0.00m",
	}
	for i, o := range lt {
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

func TestParseDS(t *testing.T) {
	dt := map[string]string{
		"example.net. 3600 IN DS 40692 12 3 22261A8B0E0D799183E35E24E2AD6BB58533CBA7E3B14D659E9CA09B 2071398F": "example.net.\t3600\tIN\tDS\t40692 12 3 22261A8B0E0D799183E35E24E2AD6BB58533CBA7E3B14D659E9CA09B2071398F",
	}
	for i, o := range dt {
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

func TestQuotes(t *testing.T) {
	tests := map[string]string{
		`t.example.com. IN TXT "a bc"`: "t.example.com.\t3600\tIN\tTXT\t\"a bc\"",
		`t.example.com. IN TXT "a
 bc"`: "t.example.com.\t3600\tIN\tTXT\t\"a\\n bc\"",
		`t.example.com. IN TXT "a"`:                                                          "t.example.com.\t3600\tIN\tTXT\t\"a\"",
		`t.example.com. IN TXT "aa"`:                                                         "t.example.com.\t3600\tIN\tTXT\t\"aa\"",
		`t.example.com. IN TXT "aaa" ;`:                                                      "t.example.com.\t3600\tIN\tTXT\t\"aaa\"",
		`t.example.com. IN TXT "abc" "DEF"`:                                                  "t.example.com.\t3600\tIN\tTXT\t\"abc\" \"DEF\"",
		`t.example.com. IN TXT "abc" ( "DEF" )`:                                              "t.example.com.\t3600\tIN\tTXT\t\"abc\" \"DEF\"",
		`t.example.com. IN TXT aaa ;`:                                                        "t.example.com.\t3600\tIN\tTXT\t\"aaa \"",
		`t.example.com. IN TXT aaa aaa;`:                                                     "t.example.com.\t3600\tIN\tTXT\t\"aaa aaa\"",
		`t.example.com. IN TXT aaa aaa`:                                                      "t.example.com.\t3600\tIN\tTXT\t\"aaa aaa\"",
		`t.example.com. IN TXT aaa`:                                                          "t.example.com.\t3600\tIN\tTXT\t\"aaa\"",
		"cid.urn.arpa. NAPTR 100 50 \"s\" \"z3950+I2L+I2C\"    \"\" _z3950._tcp.gatech.edu.": "cid.urn.arpa.\t3600\tIN\tNAPTR\t100 50 \"s\" \"z3950+I2L+I2C\" \"\" _z3950._tcp.gatech.edu.",
		"cid.urn.arpa. NAPTR 100 50 \"s\" \"rcds+I2C\"         \"\" _rcds._udp.gatech.edu.":  "cid.urn.arpa.\t3600\tIN\tNAPTR\t100 50 \"s\" \"rcds+I2C\" \"\" _rcds._udp.gatech.edu.",
		"cid.urn.arpa. NAPTR 100 50 \"s\" \"http+I2L+I2C+I2R\" \"\" _http._tcp.gatech.edu.":  "cid.urn.arpa.\t3600\tIN\tNAPTR\t100 50 \"s\" \"http+I2L+I2C+I2R\" \"\" _http._tcp.gatech.edu.",
		"cid.urn.arpa. NAPTR 100 10 \"\" \"\" \"/urn:cid:.+@([^\\.]+\\.)(.*)$/\\2/i\" .":     "cid.urn.arpa.\t3600\tIN\tNAPTR\t100 10 \"\" \"\" \"/urn:cid:.+@([^\\.]+\\.)(.*)$/\\2/i\" .",
	}
	for i, o := range tests {
		rr, e := NewRR(i)
		if e != nil {
			t.Log("Failed to parse RR: " + e.Error())
			t.Fail()
			continue
		}
		if rr.String() != o {
			t.Logf("`%s' should be equal to\n`%s', but is\n`%s'\n", i, o, rr.String())
			t.Fail()
		} else {
			t.Logf("RR is OK: `%s'", rr.String())
		}
	}
}

func TestParseBrace(t *testing.T) {
	tests := map[string]string{
		"(miek.nl.) 3600 IN A 127.0.1.1":                 "miek.nl.\t3600\tIN\tA\t127.0.1.1",
		"miek.nl. (3600) IN MX (10) elektron.atoom.net.": "miek.nl.\t3600\tIN\tMX\t10 elektron.atoom.net.",
		`miek.nl. IN (
                        3600 A 127.0.0.1)`: "miek.nl.\t3600\tIN\tA\t127.0.0.1",
		"(miek.nl.) (A) (127.0.2.1)":                          "miek.nl.\t3600\tIN\tA\t127.0.2.1",
		"miek.nl A 127.0.3.1":                                 "miek.nl.\t3600\tIN\tA\t127.0.3.1",
		"_ssh._tcp.local. 60 IN (PTR) stora._ssh._tcp.local.": "_ssh._tcp.local.\t60\tIN\tPTR\tstora._ssh._tcp.local.",
		"miek.nl. NS ns.miek.nl":                              "miek.nl.\t3600\tIN\tNS\tns.miek.nl.",
		`(miek.nl.) (
                        (IN) 
                        (AAAA)
                        (::1) )`: "miek.nl.\t3600\tIN\tAAAA\t::1",
		`(miek.nl.) (
                        (IN) 
                        (AAAA)
                        (::1))`: "miek.nl.\t3600\tIN\tAAAA\t::1",
		"miek.nl. IN AAAA ::2": "miek.nl.\t3600\tIN\tAAAA\t::2",
		`((m)(i)ek.(n)l.) (SOA) (soa.) (soa.) (
                                2009032802 ; serial
                                21600      ; refresh (6 hours)
                                7(2)00       ; retry (2 hours)
                                604()800     ; expire (1 week)
                                3600       ; minimum (1 hour)
                        )`: "miek.nl.\t3600\tIN\tSOA\tsoa. soa. 2009032802 21600 7200 604800 3600",
		"miek\\.nl. IN A 127.0.0.10": "miek\\.nl.\t3600\tIN\tA\t127.0.0.10",
		"miek.nl. IN A 127.0.0.11":   "miek.nl.\t3600\tIN\tA\t127.0.0.11",
		"miek.nl. A 127.0.0.12":      "miek.nl.\t3600\tIN\tA\t127.0.0.12",
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
			t.Log("Failed to parse RR: " + e.Error() + "\n\t" + i)
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

/*
// A bit useless, how to use b.N?. It always returns 0
func BenchmarkZoneParsing(b *testing.B) {
	b.StopTimer()
	f, err := os.Open("t/miek.nl.signed_test")
	if err != nil {
		return
	}
	defer f.Close()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		to := ParseZone(f, "", "t/miek.nl.signed_test")
		for _ = range to {
		}
	}
}
*/

func TestZoneParsing(t *testing.T) {
	f, err := os.Open("t/miek.nl.signed_test")
	if err != nil {
		return
	}
	defer f.Close()
	start := time.Now().UnixNano()
	to := ParseZone(f, "", "t/miek.nl.signed_test")
	var i int
	for x := range to {
		t.Logf("%s\n", x.RR)
		i++
	}
	delta := time.Now().UnixNano() - start
	t.Logf("%d RRs parsed in %.2f s (%.2f RR/s)", i, float32(delta)/1e9, float32(i)/(float32(delta)/1e9))
}

func ExampleZone() {
	zone := `$ORIGIN .
$TTL 3600       ; 1 hour
name                    IN SOA  a6.nstld.com. hostmaster.nic.name. (
                                203362132  ; serial
                                300        ; refresh (5 minutes)
                                300        ; retry (5 minutes)
                                1209600    ; expire (2 weeks)
                                300        ; minimum (5 minutes)
                                )
$TTL 10800      ; 3 hours
name.	10800	IN	NS	name.
               IN       NS      g6.nstld.com.
               7200     NS      h6.nstld.com.
             3600 IN    NS      j6.nstld.com.
             IN 3600    NS      k6.nstld.com.
                        NS      l6.nstld.com.
                        NS      a6.nstld.com.
                        NS      c6.nstld.com.
                        NS      d6.nstld.com.
                        NS      f6.nstld.com.
                        NS      m6.nstld.com.
( 
			NS	m7.nstld.com.
)
$ORIGIN name.
0-0onlus                NS      ns7.ehiweb.it.
                        NS      ns8.ehiweb.it.
0-g                     MX      10 mx01.nic
                        MX      10 mx02.nic
                        MX      10 mx03.nic
                        MX      10 mx04.nic
$ORIGIN 0-g.name
moutamassey             NS      ns01.yahoodomains.jp.
                        NS      ns02.yahoodomains.jp.
`
	to := ParseZone(strings.NewReader(zone), "", "testzone")
	for x := range to {
		fmt.Printf("%s\n", x.RR)
	}
	// Output:
	// name.	3600	IN	SOA	a6.nstld.com. hostmaster.nic.name. 203362132 300 300 1209600 300
	// name.	10800	IN	NS	name.
	// name.	10800	IN	NS	g6.nstld.com.
	// name.	7200	IN	NS	h6.nstld.com.
	// name.	3600	IN	NS	j6.nstld.com.
	// name.	3600	IN	NS	k6.nstld.com.
	// name.	10800	IN	NS	l6.nstld.com.
	// name.	10800	IN	NS	a6.nstld.com.
	// name.	10800	IN	NS	c6.nstld.com.
	// name.	10800	IN	NS	d6.nstld.com.
	// name.	10800	IN	NS	f6.nstld.com.
	// name.	10800	IN	NS	m6.nstld.com.
	// name.	10800	IN	NS	m7.nstld.com.
	// 0-0onlus.name.	10800	IN	NS	ns7.ehiweb.it.
	// 0-0onlus.name.	10800	IN	NS	ns8.ehiweb.it.
	// 0-g.name.	10800	IN	MX	10 mx01.nic.name.
	// 0-g.name.	10800	IN	MX	10 mx02.nic.name.
	// 0-g.name.	10800	IN	MX	10 mx03.nic.name.
	// 0-g.name.	10800	IN	MX	10 mx04.nic.name.
	// moutamassey.0-g.name.name.	10800	IN	NS	ns01.yahoodomains.jp.
	// moutamassey.0-g.name.name.	10800	IN	NS	ns02.yahoodomains.jp.
}

func ExampleHIP() {
	h := `www.example.com      IN  HIP ( 2 200100107B1A74DF365639CC39F1D578
                AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p
9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQ
b1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D
        rvs.example.com. )`
	if hip, err := NewRR(h); err == nil {
		fmt.Printf("%s\n", hip.String())
	}
	// Output:
	// www.example.com.	3600	IN	HIP	 2 200100107B1A74DF365639CC39F1D578 AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D rvs.example.com.
}

func ExampleSOA() {
	s := "example.com. 1000 SOA master.example.com. admin.example.com. 1 4294967294 4294967293 4294967295 100"
	if soa, err := NewRR(s); err == nil {
		fmt.Printf("%s\n", soa.String())
	}
	// Output:
	// example.com.	1000	IN	SOA	master.example.com. admin.example.com. 1 4294967294 4294967293 4294967295 100
}

func TestLineNumberError(t *testing.T) {
	s := "example.com. 1000 SOA master.example.com. admin.example.com. monkey 4294967294 4294967293 4294967295 100"
	if _, err := NewRR(s); err != nil {
		if err.Error() != "dns: bad SOA zone parameter: \"monkey\" at line: 1:68" {
			t.Logf("Not expecting this error: " + err.Error())
			t.Fail()
		}
	}
}

// Test with no known RR on the line
func TestLineNumberError2(t *testing.T) {
	tests := map[string]string{
		"example.com. 1000 SO master.example.com. admin.example.com. 1 4294967294 4294967293 4294967295 100": "dns: expecting RR type or class, not this...: \"SO\" at line: 1:21",
		"example.com 1000 IN TALINK a.example.com. b..example.com.":                                          "dns: bad TALINK NextName: \"b..example.com.\" at line: 1:57",
		"example.com 1000 IN TALINK ( a.example.com. b..example.com. )":                                      "dns: bad TALINK NextName: \"b..example.com.\" at line: 1:60",
		`example.com 1000 IN TALINK ( a.example.com. 
	bb..example.com. )`: "dns: bad TALINK NextName: \"bb..example.com.\" at line: 2:18",
		// This is a bug, it should report an error on line 1, but the new is already processed.
		`example.com 1000 IN TALINK ( a.example.com.  b...example.com.
	)`: "dns: bad TALINK NextName: \"b...example.com.\" at line: 2:1"}

	for in, err := range tests {
		_, e := NewRR(in)
		if e == nil {
			t.Fail()
		} else {
			if e.Error() != err {
				t.Logf("%s\n", in)
				t.Logf("Error should be %s is %s\n", err, e.Error())
				t.Fail()
			}
		}
	}
}

// Test if the calculations are correct
func TestRfc1982(t *testing.T) {
	// If the current time and the timestamp are more than 68 years apart
	// it means the date has wrapped. 0 is 1970

	// fall in the current 68 year span
	strtests := []string{"20120525134203", "19700101000000", "20380119031408"}
	for _, v := range strtests {
		if x, _ := StringToTime(v); v != TimeToString(x) {
			t.Logf("1982 arithmetic string failure %s (%s:%d)", v, TimeToString(x), x)
			t.Fail()
		}
	}

	inttests := map[uint32]string{0: "19700101000000",
		1 << 31:   "20380119031408",
		1<<32 - 1: "21060207062815",
	}
	for i, v := range inttests {
		if TimeToString(i) != v {
			t.Logf("1982 arithmetic int failure %d:%s (%s)", i, v, TimeToString(i))
			t.Fail()
		}
	}

	// Future tests, these dates get parsed to a date within the current 136 year span
	future := map[string]string{"22680119031408": "20631123173144",
		"19010101121212": "20370206184028",
		"19210101121212": "20570206184028",
		"19500101121212": "20860206184028",
		"19700101000000": "19700101000000",
		"19690101000000": "21050207062816",
		"29210101121212": "21040522212236",
	}
	for from, to := range future {
		x, _ := StringToTime(from)
		y := TimeToString(x)
		if y != to {
			t.Logf("1982 arithmetic future failure %s:%s (%s)", from, to, y)
			t.Fail()
		}
	}
}

func TestEmpty(t *testing.T) {
	for _ = range ParseZone(strings.NewReader(""), "", "") {
		t.Logf("Should be empty")
		t.Fail()
	}
}

func ExampleGenerate() {
	// From the manual: http://www.bind9.net/manual/bind/9.3.2/Bv9ARM.ch06.html#id2566761
	zone := "$GENERATE 1-2 0 NS SERVER$.EXAMPLE.\n$GENERATE 1-8 $ CNAME $.0"
	to := ParseZone(strings.NewReader(zone), "0.0.192.IN-ADDR.ARPA.", "")
	for x := range to {
		if x.Error == nil {
			fmt.Printf("%s\n", x.RR.String())
		}
	}
	// Output:
	// 0.0.0.192.IN-ADDR.ARPA.	3600	IN	NS	SERVER1.EXAMPLE.
	// 0.0.0.192.IN-ADDR.ARPA.	3600	IN	NS	SERVER2.EXAMPLE.
	// 1.0.0.192.IN-ADDR.ARPA.	3600	IN	CNAME	1.0.0.0.192.IN-ADDR.ARPA.
	// 2.0.0.192.IN-ADDR.ARPA.	3600	IN	CNAME	2.0.0.0.192.IN-ADDR.ARPA.
	// 3.0.0.192.IN-ADDR.ARPA.	3600	IN	CNAME	3.0.0.0.192.IN-ADDR.ARPA.
	// 4.0.0.192.IN-ADDR.ARPA.	3600	IN	CNAME	4.0.0.0.192.IN-ADDR.ARPA.
	// 5.0.0.192.IN-ADDR.ARPA.	3600	IN	CNAME	5.0.0.0.192.IN-ADDR.ARPA.
	// 6.0.0.192.IN-ADDR.ARPA.	3600	IN	CNAME	6.0.0.0.192.IN-ADDR.ARPA.
	// 7.0.0.192.IN-ADDR.ARPA.	3600	IN	CNAME	7.0.0.0.192.IN-ADDR.ARPA.
	// 8.0.0.192.IN-ADDR.ARPA.	3600	IN	CNAME	8.0.0.0.192.IN-ADDR.ARPA.
}

func TestSRVPacking(t *testing.T) {
	msg := Msg{}

	things := []string{"1.2.3.4:8484",
		"45.45.45.45:8484",
		"84.84.84.84:8484",
	}

	for i, n := range things {
		h, p, err := net.SplitHostPort(n)
		if err != nil {
			continue
		}
		port := 8484
		tmp, err := strconv.Atoi(p)
		if err == nil {
			port = tmp
		}

		rr := &SRV{
			Hdr: RR_Header{Name: "somename.",
				Rrtype: TypeSRV,
				Class:  ClassINET,
				Ttl:    5},
			Priority: uint16(i),
			Weight:   5,
			Port:     uint16(port),
			Target:   h + ".",
		}

		msg.Answer = append(msg.Answer, rr)
	}

	_, err := msg.Pack()
	if err != nil {
		t.Fatalf("Couldn't pack %v\n", msg)
	}
}

func TestParseBackslash(t *testing.T) {
	if r, e := NewRR("nul\\000gap.test.globnix.net. 600 IN	A 192.0.2.10"); e != nil {
		t.Fatalf("Could not create RR with \\000 in it")
	} else {
		t.Logf("Parsed %s\n", r.String())
	}
	if r, e := NewRR(`nul\000gap.test.globnix.net. 600 IN TXT "Hello\123"`); e != nil {
		t.Fatalf("Could not create RR with \\000 in it")
	} else {
		t.Logf("Parsed %s\n", r.String())
	}
}

func TestILNP(t *testing.T) {
	tests := []string{
		"host1.example.com.\t3600\tIN\tNID\t10 0014:4fff:ff20:ee64",
		"host1.example.com.\t3600\tIN\tNID\t20 0015:5fff:ff21:ee65",
		"host2.example.com.\t3600\tIN\tNID\t10 0016:6fff:ff22:ee66",
		"host1.example.com.\t3600\tIN\tL32\t10 10.1.2.0",
		"host1.example.com.\t3600\tIN\tL32\t20 10.1.4.0",
		"host2.example.com.\t3600\tIN\tL32\t10 10.1.8.0",
		"host1.example.com.\t3600\tIN\tL64\t10 2001:0DB8:1140:1000",
		"host1.example.com.\t3600\tIN\tL64\t20 2001:0DB8:2140:2000",
		"host2.example.com.\t3600\tIN\tL64\t10 2001:0DB8:4140:4000",
		"host1.example.com.\t3600\tIN\tLP\t10 l64-subnet1.example.com.",
		"host1.example.com.\t3600\tIN\tLP\t10 l64-subnet2.example.com.",
		"host1.example.com.\t3600\tIN\tLP\t20 l32-subnet1.example.com.",
	}
	for _, t1 := range tests {
		r, e := NewRR(t1)
		if e != nil {
			t.Fatalf("An error occured: %s\n", e.Error())
		} else {
			if t1 != r.String() {
				t.Fatalf("Strings should be equal %s %s", t1, r.String())
			}
		}
	}
}

func TestComment(t *testing.T) {
	// Comments we must see
	comments := map[string]bool{"; this is comment 1": true,
		"; this is comment 4": true, "; this is comment 6": true,
		"; this is comment 7": true, "; this is comment 8": true}
	zone := `
foo. IN A 10.0.0.1 ; this is comment 1
foo. IN A (
	10.0.0.2 ; this is comment2
)
; this is comment3
foo. IN A 10.0.0.3
foo. IN A ( 10.0.0.4 ); this is comment 4

foo. IN A 10.0.0.5
; this is comment5

foo. IN A 10.0.0.6

foo. IN DNSKEY 256 3 5 AwEAAb+8l ; this is comment 6
foo. IN NSEC miek.nl. TXT RRSIG NSEC; this is comment 7
foo. IN TXT "THIS IS TEXT MAN"; this is comment 8
`
	for x := range ParseZone(strings.NewReader(zone), ".", "") {
		if x.Error == nil {
			if x.Comment != "" {
				if _, ok := comments[x.Comment]; !ok {
					t.Logf("wrong comment %s", x.Comment)
					t.Fail()
				}
			}
		}
	}
}

func TestEUIxx(t *testing.T) {
	tests := map[string]string{
		"host.example. IN EUI48 00-00-5e-90-01-2a":       "host.example.\t3600\tIN\tEUI48\t00-00-5e-90-01-2a",
		"host.example. IN EUI64 00-00-5e-ef-00-00-00-2a": "host.example.\t3600\tIN\tEUI64\t00-00-5e-ef-00-00-00-2a",
	}
	for i, o := range tests {
		r, e := NewRR(i)
		if e != nil {
			t.Logf("Failed to parse %s: %s\n", i, e.Error())
			t.Fail()
		}
		if r.String() != o {
			t.Logf("Want %s, got %s\n", o, r.String())
			t.Fail()
		}
	}
}

func TestUserRR(t *testing.T) {
	tests := map[string]string{
		"host.example. IN UID 1234":              "host.example.\t3600\tIN\tUID\t1234",
		"host.example. IN GID 1234556":           "host.example.\t3600\tIN\tGID\t1234556",
		"host.example. IN UINFO \"Miek Gieben\"": "host.example.\t3600\tIN\tUINFO\t\"Miek Gieben\"",
	}
	for i, o := range tests {
		r, e := NewRR(i)
		if e != nil {
			t.Logf("Failed to parse %s: %s\n", i, e.Error())
			t.Fail()
		}
		if r.String() != o {
			t.Logf("Want %s, got %s\n", o, r.String())
			t.Fail()
		}
	}
}

func TestTXT(t *testing.T) {
	// Test single entry TXT record
	rr, err := NewRR(`_raop._tcp.local. 60 IN TXT "single value"`)
	if err != nil {
		t.Error("Failed to parse single value TXT record", err)
	} else if rr, ok := rr.(*TXT); !ok {
		t.Error("Wrong type, record should be of type TXT")
	} else {
		if len(rr.Txt) != 1 {
			t.Error("Bad size of TXT value:", len(rr.Txt))
		} else if rr.Txt[0] != "single value" {
			t.Error("Bad single value")
		}
		if rr.String() != `_raop._tcp.local.	60	IN	TXT	"single value"` {
			t.Error("Bad representation of TXT record:", rr.String())
		}
		if rr.len() == 10 {
			t.Error("Bad size of serialized record:", rr.len())
		}
	}

	// Test multi entries TXT record
	rr, err = NewRR(`_raop._tcp.local. 60 IN TXT "a=1" "b=2" "c=3" "d=4"`)
	if err != nil {
		t.Error("Failed to parse multi-values TXT record", err)
	} else if rr, ok := rr.(*TXT); !ok {
		t.Error("Wrong type, record should be of type TXT")
	} else {
		if len(rr.Txt) != 4 {
			t.Error("Bad size of TXT multi-value:", len(rr.Txt))
		} else if rr.Txt[0] != "a=1" || rr.Txt[1] != "b=2" || rr.Txt[2] != "c=3" || rr.Txt[3] != "d=4" {
			t.Error("Bad values in TXT records")
		}
		if rr.String() != `_raop._tcp.local.	60	IN	TXT	"a=1" "b=2" "c=3" "d=4"` {
			t.Error("Bad representation of TXT multi value record:", rr.String())
		}
		if rr.len() != 44 {
			t.Error("Bad size of serialized multi value record:", rr.len())
		}
	}
}

func TestRR(t *testing.T) {
	rr, err := NewRR("example.com IN TYPE1234 \\# 4 aabbccdd")
	if err == nil {
		t.Log("%s\n", rr.String())
	} else {
		t.Error("Failed to parse TYPE1234 RR: ", err.Error())
	}
	rr, err = NewRR("example.com IN TYPE1 \\# 4 0a000001")
	if err == nil {
		t.Error("This should not work")
	}
}

func TestPTR(t *testing.T) {
	_, err := NewRR("144.2.0.192.in-addr.arpa. 900 IN PTR ilouse03146p0\\(.example.com.")
	if err != nil {
		t.Error("Failed to parse ", err.Error())
	}
}

func TestDigit(t *testing.T) {
	tests := map[string]byte{
		"miek\\000.nl. 100 IN TXT \"A\"": 0,
		"miek\\001.nl. 100 IN TXT \"A\"": 1,
		"miek\\254.nl. 100 IN TXT \"A\"": 254,
		"miek\\255.nl. 100 IN TXT \"A\"": 255,
		"miek\\256.nl. 100 IN TXT \"A\"": 0,
		"miek\\257.nl. 100 IN TXT \"A\"": 1,
		"miek\\004.nl. 100 IN TXT \"A\"": 4,
	}
	for s, i := range tests {
		r, e := NewRR(s)
		buf := make([]byte, 40)
		if e != nil {
			t.Fatalf("Failed to parse %s\n", e.Error())
		}
		PackRR(r, buf, 0, nil, false)
		t.Logf("%v\n", buf)
		if buf[5] != i {
			t.Fatalf("5 pos must be %d, is %d", i, buf[5])
		}
		r1, _, _ := UnpackRR(buf, 0)
		if r1.Header().Ttl != 100 {
			t.Fatalf("Ttl should %d, is %d", 100, r1.Header().Ttl)
		}
	}
}
