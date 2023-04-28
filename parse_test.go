package dns

import (
	"bytes"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"testing/quick"
)

func TestDotInName(t *testing.T) {
	buf := make([]byte, 20)
	PackDomainName("aa\\.bb.nl.", buf, 0, nil, false)
	// index 3 must be a real dot
	if buf[3] != '.' {
		t.Error("dot should be a real dot")
	}

	if buf[6] != 2 {
		t.Error("this must have the value 2")
	}
	dom, _, _ := UnpackDomainName(buf, 0)
	// printing it should yield the backspace again
	if dom != "aa\\.bb.nl." {
		t.Error("dot should have been escaped: ", dom)
	}
}

func TestDotLastInLabel(t *testing.T) {
	sample := "aa\\..au."
	buf := make([]byte, 20)
	_, err := PackDomainName(sample, buf, 0, nil, false)
	if err != nil {
		t.Fatalf("unexpected error packing domain: %v", err)
	}
	dom, _, _ := UnpackDomainName(buf, 0)
	if dom != sample {
		t.Fatalf("unpacked domain `%s' doesn't match packed domain", dom)
	}
}

func TestTooLongDomainName(t *testing.T) {
	l := "aaabbbcccdddeeefffggghhhiiijjjkkklllmmmnnnooopppqqqrrrsssttt."
	dom := l + l + l + l + l + l + l
	_, err := NewRR(dom + " IN A 127.0.0.1")
	if err == nil {
		t.Error("should be too long")
	}
	_, err = NewRR("..com. IN A 127.0.0.1")
	if err == nil {
		t.Error("should fail")
	}
}

func TestDomainName(t *testing.T) {
	tests := []string{"r\\.gieben.miek.nl.", "www\\.www.miek.nl.",
		"www.*.miek.nl.", "www.*.miek.nl.",
	}
	dbuff := make([]byte, 40)

	for _, ts := range tests {
		if _, err := PackDomainName(ts, dbuff, 0, nil, false); err != nil {
			t.Error("not a valid domain name")
			continue
		}
		n, _, err := UnpackDomainName(dbuff, 0)
		if err != nil {
			t.Error("failed to unpack packed domain name")
			continue
		}
		if ts != n {
			t.Errorf("must be equal: in: %s, out: %s", ts, n)
		}
	}
}

func TestDomainNameAndTXTEscapes(t *testing.T) {
	tests := []byte{'.', '(', ')', ';', ' ', '@', '"', '\\', 9, 13, 10, 0, 255}
	for _, b := range tests {
		rrbytes := []byte{
			1, b, 0, // owner
			byte(TypeTXT >> 8), byte(TypeTXT),
			byte(ClassINET >> 8), byte(ClassINET),
			0, 0, 0, 1, // TTL
			0, 2, 1, b, // Data
		}
		rr1, _, err := UnpackRR(rrbytes, 0)
		if err != nil {
			panic(err)
		}
		s := rr1.String()
		rr2, err := NewRR(s)
		if err != nil {
			t.Errorf("error parsing unpacked RR's string: %v", err)
		}
		repacked := make([]byte, len(rrbytes))
		if _, err := PackRR(rr2, repacked, 0, nil, false); err != nil {
			t.Errorf("error packing parsed RR: %v", err)
		}
		if !bytes.Equal(repacked, rrbytes) {
			t.Error("packed bytes don't match original bytes")
		}
	}
}

func TestTXTEscapeParsing(t *testing.T) {
	test := [][]string{
		{`";"`, `";"`},
		{`\;`, `";"`},
		{`"\t"`, `"t"`},
		{`"\r"`, `"r"`},
		{`"\ "`, `" "`},
		{`"\;"`, `";"`},
		{`"\;\""`, `";\""`},
		{`"\(a\)"`, `"(a)"`},
		{`"\(a)"`, `"(a)"`},
		{`"(a\)"`, `"(a)"`},
		{`"(a)"`, `"(a)"`},
		{`"\048"`, `"0"`},
		{`"\` + "\t" + `"`, `"\009"`},
		{`"\` + "\n" + `"`, `"\010"`},
		{`"\` + "\r" + `"`, `"\013"`},
		{`"\` + "\x11" + `"`, `"\017"`},
		{`"\'"`, `"'"`},
	}
	for _, s := range test {
		rr, err := NewRR(fmt.Sprintf("example.com. IN TXT %v", s[0]))
		if err != nil {
			t.Errorf("could not parse %v TXT: %s", s[0], err)
			continue
		}

		txt := sprintTxt(rr.(*TXT).Txt)
		if txt != s[1] {
			t.Errorf("mismatch after parsing `%v` TXT record: `%v` != `%v`", s[0], txt, s[1])
		}
	}
}

func GenerateDomain(r *rand.Rand, size int) []byte {
	dnLen := size % 70 // artificially limit size so there's less to interpret if a failure occurs
	var dn []byte
	done := false
	for i := 0; i < dnLen && !done; {
		max := dnLen - i
		if max > 63 {
			max = 63
		}
		lLen := max
		if lLen != 0 {
			lLen = int(r.Int31()) % max
		}
		done = lLen == 0
		if done {
			continue
		}
		l := make([]byte, lLen+1)
		l[0] = byte(lLen)
		for j := 0; j < lLen; j++ {
			l[j+1] = byte(rand.Int31())
		}
		dn = append(dn, l...)
		i += 1 + lLen
	}
	return append(dn, 0)
}

func TestDomainQuick(t *testing.T) {
	r := rand.New(rand.NewSource(0))
	f := func(l int) bool {
		db := GenerateDomain(r, l)
		ds, _, err := UnpackDomainName(db, 0)
		if err != nil {
			panic(err)
		}
		buf := make([]byte, 255)
		off, err := PackDomainName(ds, buf, 0, nil, false)
		if err != nil {
			t.Errorf("error packing domain: %v", err)
			t.Errorf(" bytes: %v", db)
			t.Errorf("string: %v", ds)
			return false
		}
		if !bytes.Equal(db, buf[:off]) {
			t.Errorf("repacked domain doesn't match original:")
			t.Errorf("src bytes: %v", db)
			t.Errorf("   string: %v", ds)
			t.Errorf("out bytes: %v", buf[:off])
			return false
		}
		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func GenerateTXT(r *rand.Rand, size int) []byte {
	rdLen := size % 300 // artificially limit size so there's less to interpret if a failure occurs
	var rd []byte
	for i := 0; i < rdLen; {
		max := rdLen - 1
		if max > 255 {
			max = 255
		}
		sLen := max
		if max != 0 {
			sLen = int(r.Int31()) % max
		}
		s := make([]byte, sLen+1)
		s[0] = byte(sLen)
		for j := 0; j < sLen; j++ {
			s[j+1] = byte(rand.Int31())
		}
		rd = append(rd, s...)
		i += 1 + sLen
	}
	return rd
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
		rr, err := NewRR(i)
		if err != nil {
			t.Error("failed to parse RR: ", err)
			continue
		}
		if rr.String() != o {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", i, o, rr.String())
		}
	}
}

func TestNSEC(t *testing.T) {
	nsectests := map[string]string{
		"nl. IN NSEC3PARAM 1 0 5 30923C44C6CBBB8F": "nl.\t3600\tIN\tNSEC3PARAM\t1 0 5 30923C44C6CBBB8F",
		"p2209hipbpnm681knjnu0m1febshlv4e.nl. IN NSEC3 1 1 5 30923C44C6CBBB8F P90DG1KE8QEAN0B01613LHQDG0SOJ0TA NS SOA TXT RRSIG DNSKEY NSEC3PARAM": "p2209hipbpnm681knjnu0m1febshlv4e.nl.\t3600\tIN\tNSEC3\t1 1 5 30923C44C6CBBB8F P90DG1KE8QEAN0B01613LHQDG0SOJ0TA NS SOA TXT RRSIG DNSKEY NSEC3PARAM",
		"localhost.dnssex.nl. IN NSEC www.dnssex.nl. A RRSIG NSEC":                                                                                 "localhost.dnssex.nl.\t3600\tIN\tNSEC\twww.dnssex.nl. A RRSIG NSEC",
		"localhost.dnssex.nl. IN NSEC www.dnssex.nl. A RRSIG NSEC TYPE65534":                                                                       "localhost.dnssex.nl.\t3600\tIN\tNSEC\twww.dnssex.nl. A RRSIG NSEC TYPE65534",
		"localhost.dnssex.nl. IN NSEC www.dnssex.nl. A RRSIG NSec Type65534":                                                                       "localhost.dnssex.nl.\t3600\tIN\tNSEC\twww.dnssex.nl. A RRSIG NSEC TYPE65534",
		"44ohaq2njb0idnvolt9ggthvsk1e1uv8.skydns.test. NSEC3 1 0 0 - 44OHAQ2NJB0IDNVOLT9GGTHVSK1E1UVA":                                             "44ohaq2njb0idnvolt9ggthvsk1e1uv8.skydns.test.\t3600\tIN\tNSEC3\t1 0 0 - 44OHAQ2NJB0IDNVOLT9GGTHVSK1E1UVA",
	}
	for i, o := range nsectests {
		rr, err := NewRR(i)
		if err != nil {
			t.Error("failed to parse RR: ", err)
			continue
		}
		if rr.String() != o {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", i, o, rr.String())
		}
	}
	rr, err := NewRR("nl. IN NSEC3PARAM 1 0 5 30923C44C6CBBB8F")
	if err != nil {
		t.Fatal("failed to parse RR: ", err)
	}
	if nsec3param, ok := rr.(*NSEC3PARAM); ok {
		if nsec3param.SaltLength != 8 {
			t.Fatalf("nsec3param saltlen %d != 8", nsec3param.SaltLength)
		}
	} else {
		t.Fatal("not nsec3 param: ", err)
	}
}

func TestParseLOC(t *testing.T) {
	lt := map[string]string{
		"SW1A2AA.find.me.uk.	LOC	51 30 12.748 N 00 07 39.611 W 0.00m 0.00m 0.00m 0.00m": "SW1A2AA.find.me.uk.\t3600\tIN\tLOC\t51 30 12.748 N 00 07 39.611 W 0m 0.00m 0.00m 0.00m",
		"SW1A2AA.find.me.uk.	LOC	51 0 0.0 N 00 07 39.611 W 0.00m 0.00m 0.00m 0.00m":     "SW1A2AA.find.me.uk.\t3600\tIN\tLOC\t51 00 0.000 N 00 07 39.611 W 0m 0.00m 0.00m 0.00m",
		"SW1A2AA.find.me.uk.	LOC	51 30 12.748 N 00 07 39.611 W 0.00m":                   "SW1A2AA.find.me.uk.\t3600\tIN\tLOC\t51 30 12.748 N 00 07 39.611 W 0m 1m 10000m 10m",
		// Exercise boundary cases
		"SW1A2AA.find.me.uk.	LOC	90 0 0.0 N 180 0 0.0 W 42849672.95 90000000.00m 90000000.00m 90000000.00m":  "SW1A2AA.find.me.uk.\t3600\tIN\tLOC\t90 00 0.000 N 180 00 0.000 W 42849672.95m 90000000m 90000000m 90000000m",
		"SW1A2AA.find.me.uk.	LOC	89 59 59.999 N 179 59 59.999 W -100000 90000000.00m 90000000.00m 90000000m": "SW1A2AA.find.me.uk.\t3600\tIN\tLOC\t89 59 59.999 N 179 59 59.999 W -100000m 90000000m 90000000m 90000000m",
		// use float64 to have enough precision.
		"example.com. LOC 42 21 43.952 N 71 5 6.344 W -24m 1m 200m 10m": "example.com.\t3600\tIN\tLOC\t42 21 43.952 N 71 05 6.344 W -24m 1m 200m 10m",
	}
	for i, o := range lt {
		rr, err := NewRR(i)
		if err != nil {
			t.Error("failed to parse RR: ", err)
			continue
		}
		if rr.String() != o {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", i, o, rr.String())
		}
	}

	// Invalid cases (out of range values)
	lt = map[string]string{ // Pair of (invalid) RDATA and the bad field name
		// One of the subfields is out of range.
		"91 0 0.0 N 00 07 39.611 W 0m":   "Latitude",
		"89 60 0.0 N 00 07 39.611 W 0m":  "Latitude",
		"89 00 60.0 N 00 07 39.611 W 0m": "Latitude",
		"1 00 -1 N 00 07 39.611 W 0m":    "Latitude",
		"0 0 0.0 N 181 00 0.0 W 0m":      "Longitude",
		"0 0 0.0 N 179 60 0.0 W 0m":      "Longitude",
		"0 0 0.0 N 179 00 60.0 W 0m":     "Longitude",
		"0 0 0.0 N 1 00 -1 W 0m":         "Longitude",

		// Each subfield is valid, but resulting latitude would be out of range.
		"90 01 00.0 N 00 07 39.611 W 0m": "Latitude",
		"0 0 0.0 N 180 01 0.0 W 0m":      "Longitude",
	}
	for rdata, field := range lt {
		_, err := NewRR(fmt.Sprintf("example.com. LOC %s", rdata))
		if err == nil || !strings.Contains(err.Error(), field) {
			t.Errorf("expected error to contain %q, but got %v", field, err)
		}
	}
}

// this tests a subroutine for the LOC RR parser.  It's complicated enough to test separately.
func TestStringToCm(t *testing.T) {
	tests := []struct {
		// Test description: the input token and the expected return values from stringToCm.
		token string
		e     uint8
		m     uint8
		ok    bool
	}{
		{"100", 4, 1, true},
		{"0100", 4, 1, true}, // leading 0 (allowed)
		{"100.99", 4, 1, true},
		{"90000000", 9, 9, true},
		{"90000000.00", 9, 9, true},
		{"0", 0, 0, true},
		{"0.00", 0, 0, true},
		{"0.01", 0, 1, true},
		{".01", 0, 1, true}, // empty 'meter' part (allowed)
		{"0.1", 1, 1, true},

		// out of range (too large)
		{"90000001", 0, 0, false},
		{"90000000.01", 0, 0, false},

		// more than 2 digits in 'cmeter' part
		{"0.000", 0, 0, false},
		{"0.001", 0, 0, false},
		{"0.999", 0, 0, false},
		// with plus or minus sign (disallowed)
		{"-100", 0, 0, false},
		{"+100", 0, 0, false},
		{"0.-10", 0, 0, false},
		{"0.+10", 0, 0, false},
		{"0a.00", 0, 0, false}, // invalid string for 'meter' part
		{".1x", 0, 0, false},   // invalid string for 'cmeter' part
		{".", 0, 0, false},     // empty 'cmeter' part (disallowed)
		{"1.", 0, 0, false},    // ditto
		{"m", 0, 0, false},     // only the "m" suffix
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.token, func(t *testing.T) {
			// In all cases the expected result is the same with or without the 'm' suffix.
			// So we test both cases using the same test code.
			for _, sfx := range []string{"", "m"} {
				token := tc.token + sfx
				e, m, ok := stringToCm(token)
				if ok != tc.ok {
					t.Fatal("unexpected validation result")
				}
				if m != tc.m {
					t.Fatalf("Expected %d, got %d", tc.m, m)
				}
				if e != tc.e {
					t.Fatalf("Expected %d, got %d", tc.e, e)
				}
			}
		})
	}
}

func TestParseDS(t *testing.T) {
	dt := map[string]string{
		"example.net. 3600 IN DS 40692 12 3 22261A8B0E0D799183E35E24E2AD6BB58533CBA7E3B14D659E9CA09B 2071398F": "example.net.\t3600\tIN\tDS\t40692 12 3 22261A8B0E0D799183E35E24E2AD6BB58533CBA7E3B14D659E9CA09B2071398F",
	}
	for i, o := range dt {
		rr, err := NewRR(i)
		if err != nil {
			t.Error("failed to parse RR: ", err)
			continue
		}
		if rr.String() != o {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", i, o, rr.String())
		}
	}
}

func TestQuotes(t *testing.T) {
	tests := map[string]string{
		`t.example.com. IN TXT "a bc"`: "t.example.com.\t3600\tIN\tTXT\t\"a bc\"",
		`t.example.com. IN TXT "a
 bc"`: "t.example.com.\t3600\tIN\tTXT\t\"a\\010 bc\"",
		`t.example.com. IN TXT ""`:              "t.example.com.\t3600\tIN\tTXT\t\"\"",
		`t.example.com. IN TXT "a"`:             "t.example.com.\t3600\tIN\tTXT\t\"a\"",
		`t.example.com. IN TXT "aa"`:            "t.example.com.\t3600\tIN\tTXT\t\"aa\"",
		`t.example.com. IN TXT "aaa" ;`:         "t.example.com.\t3600\tIN\tTXT\t\"aaa\"",
		`t.example.com. IN TXT "abc" "DEF"`:     "t.example.com.\t3600\tIN\tTXT\t\"abc\" \"DEF\"",
		`t.example.com. IN TXT "abc" ( "DEF" )`: "t.example.com.\t3600\tIN\tTXT\t\"abc\" \"DEF\"",
		`t.example.com. IN TXT aaa ;`:           "t.example.com.\t3600\tIN\tTXT\t\"aaa\"",
		`t.example.com. IN TXT aaa aaa;`:        "t.example.com.\t3600\tIN\tTXT\t\"aaa\" \"aaa\"",
		`t.example.com. IN TXT aaa aaa`:         "t.example.com.\t3600\tIN\tTXT\t\"aaa\" \"aaa\"",
		`t.example.com. IN TXT aaa`:             "t.example.com.\t3600\tIN\tTXT\t\"aaa\"",
		"cid.urn.arpa. NAPTR 100 50 \"s\" \"z3950+I2L+I2C\"    \"\" _z3950._tcp.gatech.edu.": "cid.urn.arpa.\t3600\tIN\tNAPTR\t100 50 \"s\" \"z3950+I2L+I2C\" \"\" _z3950._tcp.gatech.edu.",
		"cid.urn.arpa. NAPTR 100 50 \"s\" \"rcds+I2C\"         \"\" _rcds._udp.gatech.edu.":  "cid.urn.arpa.\t3600\tIN\tNAPTR\t100 50 \"s\" \"rcds+I2C\" \"\" _rcds._udp.gatech.edu.",
		"cid.urn.arpa. NAPTR 100 50 \"s\" \"http+I2L+I2C+I2R\" \"\" _http._tcp.gatech.edu.":  "cid.urn.arpa.\t3600\tIN\tNAPTR\t100 50 \"s\" \"http+I2L+I2C+I2R\" \"\" _http._tcp.gatech.edu.",
		"cid.urn.arpa. NAPTR 100 10 \"\" \"\" \"/urn:cid:.+@([^\\.]+\\.)(.*)$/\\2/i\" .":     "cid.urn.arpa.\t3600\tIN\tNAPTR\t100 10 \"\" \"\" \"/urn:cid:.+@([^\\.]+\\.)(.*)$/\\2/i\" .",
	}
	for i, o := range tests {
		rr, err := NewRR(i)
		if err != nil {
			t.Error("failed to parse RR: ", err)
			continue
		}
		if rr.String() != o {
			t.Errorf("`%s' should be equal to\n`%s', but is\n`%s'", i, o, rr.String())
		}
	}
}

func TestParseClass(t *testing.T) {
	tests := map[string]string{
		"t.example.com. IN A 127.0.0.1": "t.example.com.	3600	IN	A	127.0.0.1",
		"t.example.com. CS A 127.0.0.1": "t.example.com.	3600	CS	A	127.0.0.1",
		"t.example.com. CH A 127.0.0.1": "t.example.com.	3600	CH	A	127.0.0.1",
		// ClassANY can not occur in zone files
		// "t.example.com. ANY A 127.0.0.1": "t.example.com.	3600	ANY	A	127.0.0.1",
		"t.example.com. NONE A 127.0.0.1":     "t.example.com.	3600	NONE	A	127.0.0.1",
		"t.example.com. CLASS255 A 127.0.0.1": "t.example.com.	3600	CLASS255	A	127.0.0.1",
	}
	for i, o := range tests {
		rr, err := NewRR(i)
		if err != nil {
			t.Error("failed to parse RR: ", err)
			continue
		}
		if rr.String() != o {
			t.Errorf("`%s' should be equal to\n`%s', but is\n`%s'", i, o, rr.String())
		}
	}
}

func TestBrace(t *testing.T) {
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
		rr, err := NewRR(i)
		if err != nil {
			t.Errorf("failed to parse RR: %v\n\t%s", err, i)
			continue
		}
		if rr.String() != o {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", i, o, rr.String())
		}
	}
}

func TestParseFailure(t *testing.T) {
	tests := []string{"miek.nl. IN A 327.0.0.1",
		"miek.nl. IN AAAA ::x",
		"miek.nl. IN MX a0 miek.nl.",
		"miek.nl aap IN MX mx.miek.nl.",
		"miek.nl 200 IN mxx 10 mx.miek.nl.",
		"miek.nl. inn MX 10 mx.miek.nl.",
		// "miek.nl. IN CNAME ", // actually valid nowadays, zero size rdata
		"miek.nl. IN CNAME ..",
		"miek.nl. PA MX 10 miek.nl.",
		"miek.nl. ) IN MX 10 miek.nl.",
	}

	for _, s := range tests {
		_, err := NewRR(s)
		if err == nil {
			t.Errorf("should have triggered an error: \"%s\"", s)
		}
	}
}

func TestOmittedTTL(t *testing.T) {
	zone := `
$ORIGIN example.com.
example.com. 42 IN SOA ns1.example.com. hostmaster.example.com. 1 86400 60 86400 3600 ; TTL=42 SOA
example.com.        NS 2 ; TTL=42 absolute owner name
@                   MD 3 ; TTL=42 current-origin owner name
                    MF 4 ; TTL=42 leading-space implied owner name
	43 TYPE65280 \# 1 05 ; TTL=43 implied owner name explicit TTL
	          MB 6       ; TTL=43 leading-tab implied owner name
$TTL 1337
example.com. 88 MG 7 ; TTL=88 explicit TTL
example.com.    MR 8 ; TTL=1337 after first $TTL
$TTL 314
             1 TXT 9 ; TTL=1 implied owner name explicit TTL
example.com.   DNAME 10 ; TTL=314 after second $TTL
`
	reCaseFromComment := regexp.MustCompile(`TTL=(\d+)\s+(.*)`)
	z := NewZoneParser(strings.NewReader(zone), "", "")
	var i int

	for rr, ok := z.Next(); ok; rr, ok = z.Next() {
		i++
		expected := reCaseFromComment.FindStringSubmatch(z.Comment())
		if len(expected) != 3 {
			t.Errorf("regexp didn't match for record %d", i)
			continue
		}
		expectedTTL, _ := strconv.ParseUint(expected[1], 10, 32)
		ttl := rr.Header().Ttl
		if ttl != uint32(expectedTTL) {
			t.Errorf("%s: expected TTL %d, got %d", expected[2], expectedTTL, ttl)
		}
	}
	if err := z.Err(); err != nil {
		t.Error(err)
	}
	if i != 10 {
		t.Errorf("expected %d records, got %d", 5, i)
	}
}

func TestRelativeNameErrors(t *testing.T) {
	var badZones = []struct {
		label        string
		zoneContents string
		expectedErr  string
	}{
		{
			"relative owner name without origin",
			"example.com 3600 IN SOA ns.example.com. hostmaster.example.com. 1 86400 60 86400 3600",
			"bad owner name",
		},
		{
			"relative owner name in RDATA",
			"example.com. 3600 IN SOA ns hostmaster 1 86400 60 86400 3600",
			"bad SOA Ns",
		},
		{
			"origin reference without origin",
			"@ 3600 IN SOA ns.example.com. hostmaster.example.com. 1 86400 60 86400 3600",
			"bad owner name",
		},
		{
			"relative owner name in $INCLUDE",
			"$INCLUDE file.db example.com",
			"bad origin name",
		},
		{
			"relative owner name in $ORIGIN",
			"$ORIGIN example.com",
			"bad origin name",
		},
	}
	for _, errorCase := range badZones {
		z := NewZoneParser(strings.NewReader(errorCase.zoneContents), "", "")
		z.Next()
		if err := z.Err(); err == nil {
			t.Errorf("%s: expected error, got nil", errorCase.label)
		} else if !strings.Contains(err.Error(), errorCase.expectedErr) {
			t.Errorf("%s: expected error `%s`, got `%s`", errorCase.label, errorCase.expectedErr, err)
		}
	}
}

func TestHIP(t *testing.T) {
	h := `www.example.com.      IN  HIP ( 2 200100107B1A74DF365639CC39F1D578
                                AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p
9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQ
b1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D
                                rvs1.example.com.
                                rvs2.example.com. )`
	rr, err := NewRR(h)
	if err != nil {
		t.Fatalf("failed to parse RR: %v", err)
	}
	msg := new(Msg)
	msg.Answer = []RR{rr, rr}
	bytes, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack msg: %v", err)
	}
	if err := msg.Unpack(bytes); err != nil {
		t.Fatalf("failed to unpack msg: %v", err)
	}
	if len(msg.Answer) != 2 {
		t.Fatalf("2 answers expected: %v", msg)
	}
	for i, rr := range msg.Answer {
		rr := rr.(*HIP)
		if l := len(rr.RendezvousServers); l != 2 {
			t.Fatalf("2 servers expected, only %d in record %d:\n%v", l, i, msg)
		}
		for j, s := range []string{"rvs1.example.com.", "rvs2.example.com."} {
			if rr.RendezvousServers[j] != s {
				t.Fatalf("expected server %d of record %d to be %s:\n%v", j, i, s, msg)
			}
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

	for in, errStr := range tests {
		_, err := NewRR(in)
		if err == nil {
			t.Error("err is nil")
		} else {
			if err.Error() != errStr {
				t.Errorf("%s: error should be %s is %v", in, errStr, err)
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
			t.Errorf("1982 arithmetic string failure %s (%s:%d)", v, TimeToString(x), x)
		}
	}

	inttests := map[uint32]string{0: "19700101000000",
		1 << 31:   "20380119031408",
		1<<32 - 1: "21060207062815",
	}
	for i, v := range inttests {
		if TimeToString(i) != v {
			t.Errorf("1982 arithmetic int failure %d:%s (%s)", i, v, TimeToString(i))
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
			t.Errorf("1982 arithmetic future failure %s:%s (%s)", from, to, y)
		}
	}
}

func TestEmpty(t *testing.T) {
	z := NewZoneParser(strings.NewReader(""), "", "")
	for _, ok := z.Next(); ok; _, ok = z.Next() {
		t.Errorf("should be empty")
	}
	if err := z.Err(); err != nil {
		t.Error("got an error when it shouldn't")
	}
}

func TestLowercaseTokens(t *testing.T) {
	var testrecords = []string{
		"example.org. 300 IN a 1.2.3.4",
		"example.org. 300 in A 1.2.3.4",
		"example.org. 300 in a 1.2.3.4",
		"example.org. 300 a 1.2.3.4",
		"example.org. 300 A 1.2.3.4",
		"example.org. IN a 1.2.3.4",
		"example.org. in A 1.2.3.4",
		"example.org. in a 1.2.3.4",
		"example.org. a 1.2.3.4",
		"example.org. A 1.2.3.4",
		"example.org. a 1.2.3.4",
		"$ORIGIN example.org.\n a 1.2.3.4",
		"$Origin example.org.\n a 1.2.3.4",
		"$origin example.org.\n a 1.2.3.4",
		"example.org. Class1 Type1 1.2.3.4",
	}
	for _, testrr := range testrecords {
		_, err := NewRR(testrr)
		if err != nil {
			t.Errorf("failed to parse %#v, got %v", testrr, err)
		}
	}
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
		port, _ := strconv.ParseUint(p, 10, 16)

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
		t.Fatalf("couldn't pack %v: %v", msg, err)
	}
}

func TestParseBackslash(t *testing.T) {
	if _, err := NewRR("nul\\000gap.test.globnix.net. 600 IN	A 192.0.2.10"); err != nil {
		t.Errorf("could not create RR with \\000 in it")
	}
	if _, err := NewRR(`nul\000gap.test.globnix.net. 600 IN TXT "Hello\123"`); err != nil {
		t.Errorf("could not create RR with \\000 in it")
	}
	if _, err := NewRR(`m\ @\ iek.nl. IN 3600 A 127.0.0.1`); err != nil {
		t.Errorf("could not create RR with \\ and \\@ in it")
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
		r, err := NewRR(t1)
		if err != nil {
			t.Fatalf("an error occurred: %v", err)
		} else {
			if t1 != r.String() {
				t.Fatalf("strings should be equal %s %s", t1, r.String())
			}
		}
	}
}

func TestGposEidNimloc(t *testing.T) {
	dt := map[string]string{
		"444433332222111199990123000000ff. NSAP-PTR foo.bar.com.": "444433332222111199990123000000ff.\t3600\tIN\tNSAP-PTR\tfoo.bar.com.",
		"lillee. IN  GPOS -32.6882 116.8652 10.0":                 "lillee.\t3600\tIN\tGPOS\t-32.6882 116.8652 10.0",
		"hinault. IN GPOS -22.6882 116.8652 250.0":                "hinault.\t3600\tIN\tGPOS\t-22.6882 116.8652 250.0",
		"VENERA.   IN NIMLOC  75234159EAC457800920":               "VENERA.\t3600\tIN\tNIMLOC\t75234159EAC457800920",
		"VAXA.     IN EID     3141592653589793":                   "VAXA.\t3600\tIN\tEID\t3141592653589793",
	}
	for i, o := range dt {
		rr, err := NewRR(i)
		if err != nil {
			t.Error("failed to parse RR: ", err)
			continue
		}
		if rr.String() != o {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", i, o, rr.String())
		}
	}
}

func TestPX(t *testing.T) {
	dt := map[string]string{
		"*.net2.it. IN PX 10 net2.it. PRMD-net2.ADMD-p400.C-it.":      "*.net2.it.\t3600\tIN\tPX\t10 net2.it. PRMD-net2.ADMD-p400.C-it.",
		"ab.net2.it. IN PX 10 ab.net2.it. O-ab.PRMD-net2.ADMDb.C-it.": "ab.net2.it.\t3600\tIN\tPX\t10 ab.net2.it. O-ab.PRMD-net2.ADMDb.C-it.",
	}
	for i, o := range dt {
		rr, err := NewRR(i)
		if err != nil {
			t.Error("failed to parse RR: ", err)
			continue
		}
		if rr.String() != o {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", i, o, rr.String())
		}
	}
}

func TestComment(t *testing.T) {
	// Comments we must see
	comments := map[string]bool{
		"; this is comment 1": true,
		"; this is comment 2": true,
		"; this is comment 4": true,
		"; this is comment 6": true,
		"; this is comment 7": true,
		"; this is comment 8": true,
	}
	zone := `
foo. IN A 10.0.0.1 ; this is comment 1
foo. IN A (
	10.0.0.2 ; this is comment 2
)
; this is comment 3
foo. IN A 10.0.0.3
foo. IN A ( 10.0.0.4 ); this is comment 4

foo. IN A 10.0.0.5
; this is comment 5

foo. IN A 10.0.0.6

foo. IN DNSKEY 256 3 5 AwEAAb+8l ; this is comment 6
foo. IN NSEC miek.nl. TXT RRSIG NSEC; this is comment 7
foo. IN TXT "THIS IS TEXT MAN"; this is comment 8
`
	z := NewZoneParser(strings.NewReader(zone), ".", "")
	for _, ok := z.Next(); ok; _, ok = z.Next() {
		if z.Comment() != "" {
			if _, okC := comments[z.Comment()]; !okC {
				t.Errorf("wrong comment %q", z.Comment())
			}
		}
	}
	if err := z.Err(); err != nil {
		t.Error("got an error when it shouldn't")
	}
}

func TestZoneParserComments(t *testing.T) {
	for i, test := range []struct {
		zone     string
		comments []string
	}{
		{
			`name. IN SOA  a6.nstld.com. hostmaster.nic.name. (
			203362132 ; serial
			5m        ; refresh (5 minutes)
			5m        ; retry (5 minutes)
			2w        ; expire (2 weeks)
			300       ; minimum (5 minutes)
		) ; y
. 3600000  IN  NS ONE.MY-ROOTS.NET. ; x`,
			[]string{"; serial ; refresh (5 minutes) ; retry (5 minutes) ; expire (2 weeks) ; minimum (5 minutes) ; y", "; x"},
		},
		{
			`name. IN SOA  a6.nstld.com. hostmaster.nic.name. (
			203362132 ; serial
			5m        ; refresh (5 minutes)
			5m        ; retry (5 minutes)
			2w        ; expire (2 weeks)
			300       ; minimum (5 minutes)
		) ; y
. 3600000  IN  NS ONE.MY-ROOTS.NET.`,
			[]string{"; serial ; refresh (5 minutes) ; retry (5 minutes) ; expire (2 weeks) ; minimum (5 minutes) ; y", ""},
		},
		{
			`name. IN SOA  a6.nstld.com. hostmaster.nic.name. (
			203362132 ; serial
			5m        ; refresh (5 minutes)
			5m        ; retry (5 minutes)
			2w        ; expire (2 weeks)
			300       ; minimum (5 minutes)
		)
. 3600000  IN  NS ONE.MY-ROOTS.NET.`,
			[]string{"; serial ; refresh (5 minutes) ; retry (5 minutes) ; expire (2 weeks) ; minimum (5 minutes)", ""},
		},
		{
			`name. IN SOA  a6.nstld.com. hostmaster.nic.name. (
			203362132 ; serial
			5m        ; refresh (5 minutes)
			5m        ; retry (5 minutes)
			2w        ; expire (2 weeks)
			300       ; minimum (5 minutes)
		)
. 3600000  IN  NS ONE.MY-ROOTS.NET. ; x`,
			[]string{"; serial ; refresh (5 minutes) ; retry (5 minutes) ; expire (2 weeks) ; minimum (5 minutes)", "; x"},
		},
		{
			`name. IN SOA  a6.nstld.com. hostmaster.nic.name. (
			203362132 ; serial
			5m        ; refresh (5 minutes)
			5m        ; retry (5 minutes)
			2w        ; expire (2 weeks)
			300       ; minimum (5 minutes)
		)`,
			[]string{"; serial ; refresh (5 minutes) ; retry (5 minutes) ; expire (2 weeks) ; minimum (5 minutes)"},
		},
		{
			`. 3600000  IN  NS ONE.MY-ROOTS.NET. ; x`,
			[]string{"; x"},
		},
		{
			`. 3600000  IN  NS ONE.MY-ROOTS.NET.`,
			[]string{""},
		},
		{
			`. 3600000  IN  NS ONE.MY-ROOTS.NET. ;;x`,
			[]string{";;x"},
		},
	} {
		r := strings.NewReader(test.zone)

		var j int
		z := NewZoneParser(r, "", "")
		for rr, ok := z.Next(); ok; rr, ok = z.Next() {
			if j >= len(test.comments) {
				t.Fatalf("too many records for zone %d at %d record, expected %d", i, j+1, len(test.comments))
			}

			if z.Comment() != test.comments[j] {
				t.Errorf("invalid comment for record %d:%d %v", i, j, rr)
				t.Logf("expected %q", test.comments[j])
				t.Logf("got      %q", z.Comment())
			}

			j++
		}

		if err := z.Err(); err != nil {
			t.Fatal(err)
		}

		if j != len(test.comments) {
			t.Errorf("too few records for zone %d, got %d, expected %d", i, j, len(test.comments))
		}
	}
}

func TestEUIxx(t *testing.T) {
	tests := map[string]string{
		"host.example. IN EUI48 00-00-5e-90-01-2a":       "host.example.\t3600\tIN\tEUI48\t00-00-5e-90-01-2a",
		"host.example. IN EUI64 00-00-5e-ef-00-00-00-2a": "host.example.\t3600\tIN\tEUI64\t00-00-5e-ef-00-00-00-2a",
	}
	for i, o := range tests {
		r, err := NewRR(i)
		if err != nil {
			t.Errorf("failed to parse %s: %v", i, err)
		}
		if r.String() != o {
			t.Errorf("want %s, got %s", o, r.String())
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
		r, err := NewRR(i)
		if err != nil {
			t.Errorf("failed to parse %s: %v", i, err)
		}
		if r.String() != o {
			t.Errorf("want %s, got %s", o, r.String())
		}
	}
}

func TestTXT(t *testing.T) {
	// Test single entry TXT record
	rr, err := NewRR(`_raop._tcp.local. 60 IN TXT "single value"`)
	if err != nil {
		t.Error("failed to parse single value TXT record", err)
	} else if rr, ok := rr.(*TXT); !ok {
		t.Error("wrong type, record should be of type TXT")
	} else {
		if len(rr.Txt) != 1 {
			t.Error("bad size of TXT value:", len(rr.Txt))
		} else if rr.Txt[0] != "single value" {
			t.Error("bad single value")
		}
		if rr.String() != `_raop._tcp.local.	60	IN	TXT	"single value"` {
			t.Error("bad representation of TXT record:", rr.String())
		}
		if Len(rr) != 28+1+12 {
			t.Error("bad size of serialized record:", Len(rr))
		}
	}

	// Test multi entries TXT record
	rr, err = NewRR(`_raop._tcp.local. 60 IN TXT "a=1" "b=2" "c=3" "d=4"`)
	if err != nil {
		t.Error("failed to parse multi-values TXT record", err)
	} else if rr, ok := rr.(*TXT); !ok {
		t.Error("wrong type, record should be of type TXT")
	} else {
		if len(rr.Txt) != 4 {
			t.Error("bad size of TXT multi-value:", len(rr.Txt))
		} else if rr.Txt[0] != "a=1" || rr.Txt[1] != "b=2" || rr.Txt[2] != "c=3" || rr.Txt[3] != "d=4" {
			t.Error("bad values in TXT records")
		}
		if rr.String() != `_raop._tcp.local.	60	IN	TXT	"a=1" "b=2" "c=3" "d=4"` {
			t.Error("bad representation of TXT multi value record:", rr.String())
		}
		if Len(rr) != 28+1+3+1+3+1+3+1+3 {
			t.Error("bad size of serialized multi value record:", Len(rr))
		}
	}

	// Test empty-string in TXT record
	rr, err = NewRR(`_raop._tcp.local. 60 IN TXT ""`)
	if err != nil {
		t.Error("failed to parse empty-string TXT record", err)
	} else if rr, ok := rr.(*TXT); !ok {
		t.Error("wrong type, record should be of type TXT")
	} else {
		if len(rr.Txt) != 1 {
			t.Error("bad size of TXT empty-string value:", len(rr.Txt))
		} else if rr.Txt[0] != "" {
			t.Error("bad value for empty-string TXT record")
		}
		if rr.String() != `_raop._tcp.local.	60	IN	TXT	""` {
			t.Error("bad representation of empty-string TXT record:", rr.String())
		}
		if Len(rr) != 28+1 {
			t.Error("bad size of serialized record:", Len(rr))
		}
	}

	// Test TXT record with chunk larger than 255 bytes, they should be split up, by the parser
	s := ""
	for i := 0; i < 255; i++ {
		s += "a"
	}
	s += "b"
	rr, err = NewRR(`test.local. 60 IN TXT "` + s + `"`)
	if err != nil {
		t.Error("failed to parse empty-string TXT record", err)
	}
	if rr.(*TXT).Txt[1] != "b" {
		t.Errorf("Txt should have two chunk, last one my be 'b', but is %s", rr.(*TXT).Txt[1])
	}
}

func TestTypeXXXX(t *testing.T) {
	_, err := NewRR("example.com IN TYPE1234 \\# 4 aabbccdd")
	if err != nil {
		t.Errorf("failed to parse TYPE1234 RR: %v", err)
	}
	_, err = NewRR("example.com IN TYPE655341 \\# 8 aabbccddaabbccdd")
	if err == nil {
		t.Errorf("this should not work, for TYPE655341")
	}
	_, err = NewRR("example.com IN TYPE1 \\# 4 0a000001")
	if err != nil {
		t.Errorf("failed to parse TYPE1 RR: %v", err)
	}
}

func TestPTR(t *testing.T) {
	_, err := NewRR("144.2.0.192.in-addr.arpa. 900 IN PTR ilouse03146p0\\(.example.com.")
	if err != nil {
		t.Error("failed to parse ", err)
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
		r, err := NewRR(s)
		buf := make([]byte, 40)
		if err != nil {
			t.Fatalf("failed to parse %v", err)
		}
		PackRR(r, buf, 0, nil, false)
		if buf[5] != i {
			t.Fatalf("5 pos must be %d, is %d", i, buf[5])
		}
		r1, _, _ := UnpackRR(buf, 0)
		if r1.Header().Ttl != 100 {
			t.Fatalf("TTL should %d, is %d", 100, r1.Header().Ttl)
		}
	}
}

func TestParseRRSIGTimestamp(t *testing.T) {
	tests := map[string]bool{
		`miek.nl.  IN RRSIG SOA 8 2 43200 20140210031301 20140111031301 12051 miek.nl. MVZUyrYwq0iZhMFDDnVXD2BvuNiUJjSYlJAgzyAE6CF875BMvvZa+Sb0 RlSCL7WODQSQHhCx/fegHhVVF+Iz8N8kOLrmXD1+jO3Bm6Prl5UhcsPx WTBsg/kmxbp8sR1kvH4oZJtVfakG3iDerrxNaf0sQwhZzyfJQAqpC7pcBoc=`: true,
		`miek.nl.  IN RRSIG SOA 8 2 43200 315565800 4102477800 12051 miek.nl. MVZUyrYwq0iZhMFDDnVXD2BvuNiUJjSYlJAgzyAE6CF875BMvvZa+Sb0 RlSCL7WODQSQHhCx/fegHhVVF+Iz8N8kOLrmXD1+jO3Bm6Prl5UhcsPx WTBsg/kmxbp8sR1kvH4oZJtVfakG3iDerrxNaf0sQwhZzyfJQAqpC7pcBoc=`:          true,
	}
	for r := range tests {
		_, err := NewRR(r)
		if err != nil {
			t.Error(err)
		}
	}
}

func TestTxtEqual(t *testing.T) {
	rr1 := new(TXT)
	rr1.Hdr = RR_Header{Name: ".", Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}
	rr1.Txt = []string{"a\"a", "\"", "b"}
	rr2, _ := NewRR(rr1.String())
	if rr1.String() != rr2.String() {
		// This is not an error, but keep this test.
		t.Errorf("these two TXT records should match:\n%s\n%s", rr1.String(), rr2.String())
	}
}

func TestTxtLong(t *testing.T) {
	rr1 := new(TXT)
	rr1.Hdr = RR_Header{Name: ".", Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}
	// Make a long txt record, this breaks when sending the packet,
	// but not earlier.
	rr1.Txt = []string{"start-"}
	for i := 0; i < 200; i++ {
		rr1.Txt[0] += "start-"
	}
	str := rr1.String()
	if len(str) < len(rr1.Txt[0]) {
		t.Error("string conversion should work")
	}
}

// Basically, don't crash.
func TestMalformedPackets(t *testing.T) {
	var packets = []string{
		"0021641c0000000100000000000078787878787878787878787303636f6d0000100001",
	}

	// com = 63 6f 6d
	for _, packet := range packets {
		data, _ := hex.DecodeString(packet)
		var msg Msg
		msg.Unpack(data)
	}
}

type algorithm struct {
	name uint8
	bits int
}

func TestNewPrivateKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	algorithms := []algorithm{
		{ECDSAP256SHA256, 256},
		{ECDSAP384SHA384, 384},
		{RSASHA1, 512},
		{RSASHA256, 512},
		{ED25519, 256},
	}

	for _, algo := range algorithms {
		key := new(DNSKEY)
		key.Hdr.Rrtype = TypeDNSKEY
		key.Hdr.Name = "miek.nl."
		key.Hdr.Class = ClassINET
		key.Hdr.Ttl = 14400
		key.Flags = 256
		key.Protocol = 3
		key.Algorithm = algo.name
		privkey, err := key.Generate(algo.bits)
		if err != nil {
			t.Fatal(err)
		}

		newPrivKey, err := key.NewPrivateKey(key.PrivateKeyString(privkey))
		if err != nil {
			t.Error(key.String())
			t.Error(key.PrivateKeyString(privkey))
			t.Fatal(err)
		}

		switch newPrivKey := newPrivKey.(type) {
		case *rsa.PrivateKey:
			newPrivKey.Precompute()
		}

		if !reflect.DeepEqual(privkey, newPrivKey) {
			t.Errorf("[%v] Private keys differ:\n%#v\n%#v", AlgorithmToString[algo.name], privkey, newPrivKey)
		}
	}
}

// special input test
func TestNewRRSpecial(t *testing.T) {
	var (
		rr     RR
		err    error
		expect string
	)

	rr, err = NewRR("; comment")
	expect = ""
	if err != nil {
		t.Errorf("unexpected err: %v", err)
	}
	if rr != nil {
		t.Errorf("unexpected result: [%s] != [%s]", rr, expect)
	}

	rr, err = NewRR("")
	expect = ""
	if err != nil {
		t.Errorf("unexpected err: %v", err)
	}
	if rr != nil {
		t.Errorf("unexpected result: [%s] != [%s]", rr, expect)
	}

	rr, err = NewRR("$ORIGIN foo.")
	expect = ""
	if err != nil {
		t.Errorf("unexpected err: %v", err)
	}
	if rr != nil {
		t.Errorf("unexpected result: [%s] != [%s]", rr, expect)
	}

	rr, err = NewRR(" ")
	expect = ""
	if err != nil {
		t.Errorf("unexpected err: %v", err)
	}
	if rr != nil {
		t.Errorf("unexpected result: [%s] != [%s]", rr, expect)
	}

	rr, err = NewRR("\n")
	expect = ""
	if err != nil {
		t.Errorf("unexpected err: %v", err)
	}
	if rr != nil {
		t.Errorf("unexpected result: [%s] != [%s]", rr, expect)
	}

	rr, err = NewRR("foo. A 1.1.1.1\nbar. A 2.2.2.2")
	expect = "foo.\t3600\tIN\tA\t1.1.1.1"
	if err != nil {
		t.Errorf("unexpected err: %v", err)
	}
	if rr == nil || rr.String() != expect {
		t.Errorf("unexpected result: [%s] != [%s]", rr, expect)
	}
}

func TestPrintfVerbsRdata(t *testing.T) {
	x, _ := NewRR("www.miek.nl. IN MX 20 mx.miek.nl.")
	if Field(x, 1) != "20" {
		t.Errorf("should be 20")
	}
	if Field(x, 2) != "mx.miek.nl." {
		t.Errorf("should be mx.miek.nl.")
	}

	x, _ = NewRR("www.miek.nl. IN A 127.0.0.1")
	if Field(x, 1) != "127.0.0.1" {
		t.Errorf("should be 127.0.0.1")
	}

	x, _ = NewRR("www.miek.nl. IN AAAA ::1")
	if Field(x, 1) != "::1" {
		t.Errorf("should be ::1")
	}

	x, _ = NewRR("www.miek.nl. IN NSEC a.miek.nl. A NS SOA MX AAAA")
	if Field(x, 1) != "a.miek.nl." {
		t.Errorf("should be a.miek.nl.")
	}
	if Field(x, 2) != "A NS SOA MX AAAA" {
		t.Errorf("should be A NS SOA MX AAAA")
	}

	x, _ = NewRR("www.miek.nl. IN TXT \"first\" \"second\"")
	if Field(x, 1) != "first second" {
		t.Errorf("should be first second")
	}
	if Field(x, 0) != "" {
		t.Errorf("should be empty")
	}
}

func TestParseTokenOverflow(t *testing.T) {
	_, err := NewRR("_443._tcp.example.org. IN TLSA 0 0 0 308205e8308204d0a00302010202100411de8f53b462f6a5a861b712ec6b59300d06092a864886f70d01010b05003070310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d312f302d06035504031326446967694365727420534841322048696768204173737572616e636520536572766572204341301e170d3134313130363030303030305a170d3135313131333132303030305a3081a5310b3009060355040613025553311330110603550408130a43616c69666f726e6961311430120603550407130b4c6f7320416e67656c6573313c303a060355040a1333496e7465726e657420436f72706f726174696f6e20666f722041737369676e6564204e616d657320616e64204e756d6265727331133011060355040b130a546563686e6f6c6f6779311830160603550403130f7777772e6578616d706c652e6f726730820122300d06092a864886f70d01010105000382010f003082010a02820101009e663f52a3d18cb67cdfed547408a4e47e4036538988da2798da3b6655f7240d693ed1cb3fe6d6ad3a9e657ff6efa86b83b0cad24e5d31ff2bf70ec3b78b213f1b4bf61bdc669cbbc07d67154128ca92a9b3cbb4213a836fb823ddd4d7cc04918314d25f06086fa9970ba17e357cca9b458c27eb71760ab95e3f9bc898ae89050ae4d09ba2f7e4259d9ff1e072a6971b18355a8b9e53670c3d5dbdbd283f93a764e71b3a4140ca0746090c08510e2e21078d7d07844bf9c03865b531a0bf2ee766bc401f6451c5a1e6f6fb5d5c1d6a97a0abe91ae8b02e89241e07353909ccd5b41c46de207c06801e08f20713603827f2ae3e68cf15ef881d7e0608f70742e30203010001a382024630820242301f0603551d230418301680145168ff90af0207753cccd9656462a212b859723b301d0603551d0e04160414b000a7f422e9b1ce216117c4c46e7164c8e60c553081810603551d11047a3078820f7777772e6578616d706c652e6f7267820b6578616d706c652e636f6d820b6578616d706c652e656475820b6578616d706c652e6e6574820b6578616d706c652e6f7267820f7777772e6578616d706c652e636f6d820f7777772e6578616d706c652e656475820f7777772e6578616d706c652e6e6574300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b0601050507030230750603551d1f046e306c3034a032a030862e687474703a2f2f63726c332e64696769636572742e636f6d2f736861322d68612d7365727665722d67332e63726c3034a032a030862e687474703a2f2f63726c342e64696769636572742e636f6d2f736861322d68612d7365727665722d67332e63726c30420603551d20043b3039303706096086480186fd6c0101302a302806082b06010505070201161c68747470733a2f2f7777772e64696769636572742e636f6d2f43505330818306082b0601050507010104773075302406082b060105050730018618687474703a2f2f6f6373702e64696769636572742e636f6d304d06082b060105050730028641687474703a2f2f636163657274732e64696769636572742e636f6d2f446967694365727453484132486967684173737572616e636553657276657243412e637274300c0603551d130101ff04023000300d06092a864886f70d01010b050003820101005eac2124dedb3978a86ff3608406acb542d3cb54cb83facd63aec88144d6a1bf15dbf1f215c4a73e241e582365cba9ea50dd306541653b3513af1a0756c1b2720e8d112b34fb67181efad9c4609bdc670fb025fa6e6d42188161b026cf3089a08369c2f3609fc84bcc3479140c1922ede430ca8dbac2b2a3cdacb305ba15dc7361c4c3a5e6daa99cb446cb221b28078a7a944efba70d96f31ac143d959bccd2fd50e30c325ea2624fb6b6dbe9344dbcf133bfbd5b4e892d635dbf31596451672c6b65ba5ac9b3cddea92b35dab1065cae3c8cb6bb450a62ea2f72ea7c6bdc7b65fa09b012392543734083c7687d243f8d0375304d99ccd2e148966a8637a6797")
	if err != nil {
		t.Fatalf("long token should not return an error")
	}
}

func TestParseTLSA(t *testing.T) {
	lt := []string{
		"_443._tcp.example.org.\t3600\tIN\tTLSA\t1 1 1 c22be239f483c08957bc106219cc2d3ac1a308dfbbdd0a365f17b9351234cf00",
		"_443._tcp.example.org.\t3600\tIN\tTLSA\t2 1 2 4e85f45179e9cd6e0e68e2eb5be2e85ec9b92d91c609caf3ef0315213e3f92ece92c38397a607214de95c7fadc0ad0f1c604a469a0387959745032c0d51492f3",
		"_443._tcp.example.org.\t3600\tIN\tTLSA\t3 0 2 69ec8d2277360b215d0cd956b0e2747108dff34b27d461a41c800629e38ee6c2d1230cc9e8e36711330adc6766e6ff7c5fbb37f106f248337c1a20ad682888d2",
	}
	for _, o := range lt {
		rr, err := NewRR(o)
		if err != nil {
			t.Error("failed to parse RR: ", err)
			continue
		}
		if rr.String() != o {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", o, o, rr.String())
		}
	}
}

func TestParseSMIMEA(t *testing.T) {
	lt := map[string]string{
		"2e85e1db3e62be6ea._smimecert.example.com.\t3600\tIN\tSMIMEA\t1 1 2 bd80f334566928fc18f58df7e4928c1886f48f71ca3fd41cd9b1854aca7c2180aaacad2819612ed68e7bd3701cc39be7f2529b017c0bc6a53e8fb3f0c7d48070":   "2e85e1db3e62be6ea._smimecert.example.com.\t3600\tIN\tSMIMEA\t1 1 2 bd80f334566928fc18f58df7e4928c1886f48f71ca3fd41cd9b1854aca7c2180aaacad2819612ed68e7bd3701cc39be7f2529b017c0bc6a53e8fb3f0c7d48070",
		"2e85e1db3e62be6ea._smimecert.example.com.\t3600\tIN\tSMIMEA\t0 0 1 cdcf0fc66b182928c5217ddd42c826983f5a4b94160ee6c1c9be62d38199f710":                                                                   "2e85e1db3e62be6ea._smimecert.example.com.\t3600\tIN\tSMIMEA\t0 0 1 cdcf0fc66b182928c5217ddd42c826983f5a4b94160ee6c1c9be62d38199f710",
		"2e85e1db3e62be6ea._smimecert.example.com.\t3600\tIN\tSMIMEA\t3 0 2 499a1eda2af8828b552cdb9d80c3744a25872fddd73f3898d8e4afa3549595d2dd4340126e759566fe8c26b251fa0c887ba4869f011a65f7e79967c2eb729f5b":   "2e85e1db3e62be6ea._smimecert.example.com.\t3600\tIN\tSMIMEA\t3 0 2 499a1eda2af8828b552cdb9d80c3744a25872fddd73f3898d8e4afa3549595d2dd4340126e759566fe8c26b251fa0c887ba4869f011a65f7e79967c2eb729f5b",
		"2e85e1db3e62be6eb._smimecert.example.com.\t3600\tIN\tSMIMEA\t3 0 2 499a1eda2af8828b552cdb9d80c3744a25872fddd73f3898d8e4afa3549595d2dd4340126e759566fe8 c26b251fa0c887ba4869f01 1a65f7e79967c2eb729f5b": "2e85e1db3e62be6eb._smimecert.example.com.\t3600\tIN\tSMIMEA\t3 0 2 499a1eda2af8828b552cdb9d80c3744a25872fddd73f3898d8e4afa3549595d2dd4340126e759566fe8c26b251fa0c887ba4869f011a65f7e79967c2eb729f5b",
	}
	for i, o := range lt {
		rr, err := NewRR(i)
		if err != nil {
			t.Error("failed to parse RR: ", err)
			continue
		}
		if rr.String() != o {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", o, o, rr.String())
		}
	}
}

func TestParseSSHFP(t *testing.T) {
	lt := []string{
		"test.example.org.\t300\tSSHFP\t1 2 (\n" +
			"\t\t\t\t\tBC6533CDC95A79078A39A56EA7635984ED655318ADA9\n" +
			"\t\t\t\t\tB6159E30723665DA95BB )",
		"test.example.org.\t300\tSSHFP\t1 2 ( BC6533CDC  95A79078A39A56EA7635984ED655318AD  A9B6159E3072366 5DA95BB )",
	}
	result := "test.example.org.\t300\tIN\tSSHFP\t1 2 BC6533CDC95A79078A39A56EA7635984ED655318ADA9B6159E30723665DA95BB"
	for _, o := range lt {
		rr, err := NewRR(o)
		if err != nil {
			t.Error("failed to parse RR: ", err)
			continue
		}
		if rr.String() != result {
			t.Errorf("`%s' should be equal to\n\n`%s', but is     \n`%s'", o, result, rr.String())
		}
	}
}

func TestParseHINFO(t *testing.T) {
	dt := map[string]string{
		"example.net. HINFO A B":         "example.net.	3600	IN	HINFO	\"A\" \"B\"",
		"example.net. HINFO \"A\" \"B\"": "example.net.	3600	IN	HINFO	\"A\" \"B\"",
		"example.net. HINFO A B C D E F": "example.net.	3600	IN	HINFO	\"A\" \"B C D E F\"",
		"example.net. HINFO AB":          "example.net.	3600	IN	HINFO	\"AB\" \"\"",
		// "example.net. HINFO PC-Intel-700mhz \"Redhat Linux 7.1\"": "example.net.	3600	IN	HINFO	\"PC-Intel-700mhz\" \"Redhat Linux 7.1\"",
		// This one is recommended in Pro Bind book http://www.zytrax.com/books/dns/ch8/hinfo.html
		// but effectively, even Bind would replace it to correctly formed text when you AXFR
		// TODO: remove this set of comments or figure support for quoted/unquoted combinations in endingToTxtSlice function
	}
	for i, o := range dt {
		rr, err := NewRR(i)
		if err != nil {
			t.Error("failed to parse RR: ", err)
			continue
		}
		if rr.String() != o {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", i, o, rr.String())
		}
	}
}

func TestParseCAA(t *testing.T) {
	lt := map[string]string{
		"example.net.	CAA	0 issue \"symantec.com\"":            "example.net.\t3600\tIN\tCAA\t0 issue \"symantec.com\"",
		"example.net.	CAA	0 issuewild \"symantec.com; stuff\"": "example.net.\t3600\tIN\tCAA\t0 issuewild \"symantec.com; stuff\"",
		"example.net.	CAA	128 tbs \"critical\"":                "example.net.\t3600\tIN\tCAA\t128 tbs \"critical\"",
		"example.net.	CAA	2 auth \"0>09\\006\\010+\\006\\001\\004\\001\\214y\\002\\003\\001\\006\\009`\\134H\\001e\\003\\004\\002\\001\\004 y\\209\\012\\221r\\220\\156Q\\218\\150\\150{\\166\\245:\\231\\182%\\157:\\133\\179}\\1923r\\238\\151\\255\\128q\\145\\002\\001\\000\"": "example.net.\t3600\tIN\tCAA\t2 auth \"0>09\\006\\010+\\006\\001\\004\\001\\214y\\002\\003\\001\\006\\009`\\134H\\001e\\003\\004\\002\\001\\004 y\\209\\012\\221r\\220\\156Q\\218\\150\\150{\\166\\245:\\231\\182%\\157:\\133\\179}\\1923r\\238\\151\\255\\128q\\145\\002\\001\\000\"",
		"example.net.   TYPE257	0 issue \"symantec.com\"": "example.net.\t3600\tIN\tCAA\t0 issue \"symantec.com\"",
	}
	for i, o := range lt {
		rr, err := NewRR(i)
		if err != nil {
			t.Error("failed to parse RR: ", err)
			continue
		}
		if rr.String() != o {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", i, o, rr.String())
		}
	}
}

func TestPackCAA(t *testing.T) {
	m := new(Msg)
	record := new(CAA)
	record.Hdr = RR_Header{Name: "example.com.", Rrtype: TypeCAA, Class: ClassINET, Ttl: 0}
	record.Tag = "issue"
	record.Value = "symantec.com"
	record.Flag = 1

	m.Answer = append(m.Answer, record)
	bytes, err := m.Pack()
	if err != nil {
		t.Fatalf("failed to pack msg: %v", err)
	}
	if err := m.Unpack(bytes); err != nil {
		t.Fatalf("failed to unpack msg: %v", err)
	}
	if len(m.Answer) != 1 {
		t.Fatalf("incorrect number of answers unpacked")
	}
	rr := m.Answer[0].(*CAA)
	if rr.Tag != "issue" {
		t.Fatalf("invalid tag for unpacked answer")
	} else if rr.Value != "symantec.com" {
		t.Fatalf("invalid value for unpacked answer")
	} else if rr.Flag != 1 {
		t.Fatalf("invalid flag for unpacked answer")
	}
}

func TestParseURI(t *testing.T) {
	lt := map[string]string{
		"_http._tcp. IN URI   10 1 \"http://www.example.com/path\"": "_http._tcp.\t3600\tIN\tURI\t10 1 \"http://www.example.com/path\"",
		"_http._tcp. IN URI   10 1 \"\"":                            "_http._tcp.\t3600\tIN\tURI\t10 1 \"\"",
	}
	for i, o := range lt {
		rr, err := NewRR(i)
		if err != nil {
			t.Error("failed to parse RR: ", err)
			continue
		}
		if rr.String() != o {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", i, o, rr.String())
		}
	}
}

func TestParseAVC(t *testing.T) {
	avcs := map[string]string{
		`example.org. IN AVC "app-name:WOLFGANG|app-class:OAM|business=yes"`: `example.org.	3600	IN	AVC	"app-name:WOLFGANG|app-class:OAM|business=yes"`,
	}
	for avc, o := range avcs {
		rr, err := NewRR(avc)
		if err != nil {
			t.Error("failed to parse RR: ", err)
			continue
		}
		if rr.String() != o {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", avc, o, rr.String())
		}
	}
}

func TestParseCSYNC(t *testing.T) {
	syncs := map[string]string{
		`example.com. 3600 IN CSYNC 66 3 A NS AAAA`: `example.com.	3600	IN	CSYNC	66 3 A NS AAAA`,
	}
	for s, o := range syncs {
		rr, err := NewRR(s)
		if err != nil {
			t.Error("failed to parse RR: ", err)
			continue
		}
		if rr.String() != o {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", s, o, rr.String())
		}
	}
}

func TestParseSVCB(t *testing.T) {
	svcbs := map[string]string{
		`example.com. 3600 IN SVCB 0 cloudflare.com.`:                              `example.com.	3600	IN	SVCB	0 cloudflare.com.`,
		`example.com. 3600 IN SVCB 65000 cloudflare.com. alpn=h2 ipv4hint=3.4.3.2`: `example.com.	3600	IN	SVCB	65000 cloudflare.com. alpn="h2" ipv4hint="3.4.3.2"`,
		`example.com. 3600 IN SVCB 65000 cloudflare.com. key65000=4\ 3 key65001="\" " key65002 key65003= key65004="" key65005== key65006==\"\" key65007=\254 key65008=\032`: `example.com.	3600	IN	SVCB	65000 cloudflare.com. key65000="4\ 3" key65001="\"\ " key65002="" key65003="" key65004="" key65005="=" key65006="=\"\"" key65007="\254" key65008="\ "`,
		// Explained in svcb.go "In AliasMode, records SHOULD NOT include any SvcParams,"
		`example.com. 3600 IN SVCB 0 no-default-alpn`: `example.com.	3600	IN	SVCB	0 no-default-alpn.`,
		// From the specification
		`example.com.   HTTPS   0 foo.example.com.`:                                                          `example.com.	3600	IN	HTTPS	0 foo.example.com.`,
		`example.com.   SVCB   1 .`:                                                                          `example.com.	3600	IN	SVCB	1 .`,
		`example.com.   SVCB   16 foo.example.com. port=53`:                                                  `example.com.	3600	IN	SVCB	16 foo.example.com. port="53"`,
		`example.com.   SVCB   1 foo.example.com. key667=hello`:                                              `example.com.	3600	IN	SVCB	1 foo.example.com. key667="hello"`,
		`example.com.   SVCB   1 foo.example.com. key667="hello\210qoo"`:                                     `example.com.	3600	IN	SVCB	1 foo.example.com. key667="hello\210qoo"`,
		`example.com.   SVCB   1 foo.example.com. ipv6hint="2001:db8::1,2001:db8::53:1"`:                     `example.com.	3600	IN	SVCB	1 foo.example.com. ipv6hint="2001:db8::1,2001:db8::53:1"`,
		`example.com.   SVCB   1 example.com. ipv6hint="2001:db8::198.51.100.100"`:                           `example.com.	3600	IN	SVCB	1 example.com. ipv6hint="2001:db8::c633:6464"`,
		`example.com.   SVCB   16 foo.example.org. alpn=h2,h3-19 mandatory=ipv4hint,alpn ipv4hint=192.0.2.1`: `example.com.	3600	IN	SVCB	16 foo.example.org. alpn="h2,h3-19" mandatory="ipv4hint,alpn" ipv4hint="192.0.2.1"`,
		`example.com.   SVCB   16 foo.example.org. alpn="f\\\\oo\\,bar,h2"`:                                  `example.com.	3600	IN	SVCB	16 foo.example.org. alpn="f\\\092oo\\\044bar,h2"`,
		`example.com.   SVCB   16 foo.example.org. alpn=f\\\092oo\092,bar,h2`:                                `example.com.	3600	IN	SVCB	16 foo.example.org. alpn="f\\\092oo\\\044bar,h2"`,
		// From draft-ietf-add-ddr-06
		`_dns.example.net. SVCB 1 example.net. alpn=h2 dohpath=/dns-query{?dns}`:     `_dns.example.net.	3600	IN	SVCB	1 example.net. alpn="h2" dohpath="/dns-query{?dns}"`,
		`_dns.example.net. SVCB 1 example.net. alpn=h2 dohpath=/dns\045query{\?dns}`: `_dns.example.net.	3600	IN	SVCB	1 example.net. alpn="h2" dohpath="/dns-query{?dns}"`,
	}
	for s, o := range svcbs {
		rr, err := NewRR(s)
		if err != nil {
			t.Error("failed to parse RR: ", err)
			continue
		}
		if rr.String() != o {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", s, o, rr.String())
		}
	}
}

func TestParseBadSVCB(t *testing.T) {
	header := `example.com. 3600 IN HTTPS `
	evils := []string{
		`65536 . no-default-alpn`, // bad priority
		`1 ..`,                    // bad domain
		`1 . no-default-alpn=1`,   // value illegal
		`1 . key`,                 // invalid key
		`1 . key=`,                // invalid key
		`1 . =`,                   // invalid key
		`1 . ==`,                  // invalid key
		`1 . =a`,                  // invalid key
		`1 . ""`,                  // invalid key
		`1 . ""=`,                 // invalid key
		`1 . "a"`,                 // invalid key
		`1 . "a"=`,                // invalid key
		`1 . key1=`,               // we know that key
		`1 . key65535`,            // key reserved
		`1 . key065534`,           // key can't be padded
		`1 . key65534="f`,         // unterminated value
		`1 . key65534="`,          // unterminated value
		`1 . key65534=\2`,         // invalid numeric escape
		`1 . key65534=\24`,        // invalid numeric escape
		`1 . key65534=\256`,       // invalid numeric escape
		`1 . key65534=\`,          // invalid numeric escape
		`1 . key65534=""alpn`,     // zQuote ending needs whitespace
		`1 . key65534="a"alpn`,    // zQuote ending needs whitespace
		`1 . ipv6hint=1.1.1.1`,    // not ipv6
		`1 . ipv6hint=1:1:1:1`,    // not ipv6
		`1 . ipv6hint=a`,          // not ipv6
		`1 . ipv6hint=`,           // empty ipv6
		`1 . ipv4hint=1.1.1.1.1`,  // not ipv4
		`1 . ipv4hint=::fc`,       // not ipv4
		`1 . ipv4hint=..11`,       // not ipv4
		`1 . ipv4hint=a`,          // not ipv4
		`1 . ipv4hint=`,           // empty ipv4
		`1 . port=`,               // empty port
		`1 . echconfig=YUd`,       // bad base64
		`1 . alpn=h\`,             // unterminated escape
		`1 . alpn=h2\\.h3`,        // comma-separated list with bad character
		`1 . alpn=h2,,h3`,         // empty protocol identifier
		`1 . alpn=h3,`,            // final protocol identifier empty
	}
	for _, o := range evils {
		_, err := NewRR(header + o)
		if err == nil {
			t.Error("failed to reject invalid RR: ", header+o)
			continue
		}
	}
}

func TestParseBadNAPTR(t *testing.T) {
	// Should look like: mplus.ims.vodafone.com.	3600	IN	NAPTR	10 100 "S" "SIP+D2U" "" _sip._udp.mplus.ims.vodafone.com.
	naptr := `mplus.ims.vodafone.com.	3600	IN	NAPTR	10 100 S SIP+D2U  _sip._udp.mplus.ims.vodafone.com.`
	_, err := NewRR(naptr) // parse fails, we should not have leaked a goroutine.
	if err == nil {
		t.Fatalf("parsing NAPTR should have failed: %s", naptr)
	}
	if err := goroutineLeaked(); err != nil {
		t.Errorf("leaked goroutines: %s", err)
	}
}

func TestUnbalancedParens(t *testing.T) {
	sig := `example.com. 3600 IN RRSIG MX 15 2 3600 (
              1440021600 1438207200 3613 example.com. (
              oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3f
              x8A4M3e23mRZ9VrbpMngwcrqNAg== )`
	_, err := NewRR(sig)
	if err == nil {
		t.Fatalf("failed to detect extra opening brace")
	}
}

func TestBad(t *testing.T) {
	tests := []string{
		`" TYPE257 9 1E12\x00\x105"`,
		`" TYPE256  9 5"`,
		`" TYPE257 0\"00000000000000400000000000000000000\x00\x10000000000000000000000000000000000 9 l\x16\x01\x005266"`,
	}
	for i := range tests {
		s, err := strconv.Unquote(tests[i])
		if err != nil {
			t.Fatalf("failed to unquote: %q: %s", tests[i], err)
		}
		if _, err = NewRR(s); err == nil {
			t.Errorf("correctly parsed %q", s)
		}
	}
}

func TestNULLRecord(t *testing.T) {
	// packet captured from iodine
	packet := `8116840000010001000000000569627a6c700474657374046d69656b026e6c00000a0001c00c000a0001000000000005497f000001`
	data, _ := hex.DecodeString(packet)
	msg := new(Msg)
	err := msg.Unpack(data)
	if err != nil {
		t.Fatalf("Failed to unpack NULL record")
	}
	if _, ok := msg.Answer[0].(*NULL); !ok {
		t.Fatalf("Expected packet to contain NULL record")
	}
}

func TestParseAPL(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		expect string
	}{
		{
			"v4",
			". APL 1:192.0.2.0/24",
			".\t3600\tIN\tAPL\t1:192.0.2.0/24",
		},
		{
			"v6",
			". APL 2:2001:db8::/32",
			".\t3600\tIN\tAPL\t2:2001:db8::/32",
		},
		{
			"null v6",
			". APL 2:::/0",
			".\t3600\tIN\tAPL\t2:::/0",
		},
		{
			"null v4",
			". APL 1:0.0.0.0/0",
			".\t3600\tIN\tAPL\t1:0.0.0.0/0",
		},
		{
			"full v6",
			". APL 2:::/0",
			".\t3600\tIN\tAPL\t2:::/0",
		},
		{
			"full v4",
			". APL 1:192.0.2.1/32",
			".\t3600\tIN\tAPL\t1:192.0.2.1/32",
		},
		{
			"full v6",
			". APL 2:2001:0db8:d2b4:b6ba:50db:49cc:a8d1:5bb1/128",
			".\t3600\tIN\tAPL\t2:2001:db8:d2b4:b6ba:50db:49cc:a8d1:5bb1/128",
		},
		{
			"v4in6",
			". APL 2:::ffff:192.0.2.0/120",
			".\t3600\tIN\tAPL\t2:::ffff:192.0.2.0/120",
		},
		{
			"v4in6 v6 syntax",
			". APL 2:::ffff:c000:0200/120",
			".\t3600\tIN\tAPL\t2:::ffff:192.0.2.0/120",
		},
		{
			"negate",
			". APL !1:192.0.2.0/24",
			".\t3600\tIN\tAPL\t!1:192.0.2.0/24",
		},
		{
			"multiple",
			". APL 1:192.0.2.0/24 !1:192.0.2.1/32 2:2001:db8::/32 !2:2001:db8:1::0/48",
			".\t3600\tIN\tAPL\t1:192.0.2.0/24 !1:192.0.2.1/32 2:2001:db8::/32 !2:2001:db8:1::/48",
		},
		{
			"no address",
			". APL",
			".\t3600\tIN\tAPL\t",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr, err := NewRR(tc.in)
			if err != nil {
				t.Fatalf("failed to parse RR: %s", err)
			}

			got := rr.String()
			if got != tc.expect {
				t.Errorf("expected %q, got %q", tc.expect, got)
			}
		})
	}
}

func TestParseAPLErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{
			"unexpected",
			`. APL ""`,
		},
		{
			"unrecognized family",
			". APL 3:0.0.0.0/0",
		},
		{
			"malformed family",
			". APL foo:0.0.0.0/0",
		},
		{
			"malformed address",
			". APL 1:192.0.2/16",
		},
		{
			"extra bits",
			". APL 2:2001:db8::/0",
		},
		{
			"address mismatch v2",
			". APL 1:2001:db8::/64",
		},
		{
			"address mismatch v6",
			". APL 2:192.0.2.1/32",
		},
		{
			"no prefix",
			". APL 1:192.0.2.1",
		},
		{
			"no family",
			". APL 0.0.0.0/0",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewRR(tc.in)
			if err == nil {
				t.Fatal("expected error, got none")
			}
		})
	}
}

func TestUnpackRRWithHeaderInvalidLengths(t *testing.T) {
	rr, err := NewRR("test.example.org. 300 IN SSHFP 1 2 BC6533CDC95A79078A39A56EA7635984ED655318ADA9B6159E30723665DA95BB")
	if err != nil {
		t.Fatalf("failed to parse SSHFP record: %v", err)
	}

	buf := make([]byte, Len(rr))
	headerEnd, end, err := packRR(rr, buf, 0, compressionMap{}, false)
	if err != nil {
		t.Fatalf("failed to pack A record: %v", err)
	}

	rr.Header().Rdlength = uint16(end - headerEnd)
	for _, off := range []int{
		-1,
		end + 1,
		1<<16 - 1,
	} {
		_, _, err := UnpackRRWithHeader(*rr.Header(), buf, off)
		if de, ok := err.(*Error); !ok || de.err != "bad off" {
			t.Errorf("UnpackRRWithHeader with bad offset (%d) returned wrong or no error: %v", off, err)
		}
	}

	for _, rdlength := range []uint16{
		uint16(end - headerEnd + 1),
		uint16(end),
		1<<16 - 1,
	} {
		rr.Header().Rdlength = rdlength

		_, _, err := UnpackRRWithHeader(*rr.Header(), buf, headerEnd)
		if de, ok := err.(*Error); !ok || de.err != "bad rdlength" {
			t.Errorf("UnpackRRWithHeader with bad rdlength (%d) returned wrong or no error: %v", rdlength, err)
		}
	}
}

func TestParseZONEMD(t *testing.T) {
	// Uses examples from https://tools.ietf.org/html/rfc8976
	dt := map[string]string{
		// Simple Zone
		`example.	86400	IN	ZONEMD	2018031900 1 1 (
										c68090d90a7aed71
										6bc459f9340e3d7c
										1370d4d24b7e2fc3
										a1ddc0b9a87153b9
										a9713b3c9ae5cc27
										777f98b8e730044c )
		`: "example.\t86400\tIN\tZONEMD\t2018031900 1 1 c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c",
		// Complex Zone
		`example.	86400	IN	ZONEMD	2018031900 1 1 (
										a3b69bad980a3504
										e1cffcb0fd6397f9
										3848071c93151f55
										2ae2f6b1711d4bd2
										d8b39808226d7b9d
										b71e34b72077f8fe )
		`: "example.\t86400\tIN\tZONEMD\t2018031900 1 1 a3b69bad980a3504e1cffcb0fd6397f93848071c93151f552ae2f6b1711d4bd2d8b39808226d7b9db71e34b72077f8fe",
		// Multiple Digests Zone
		`example.	86400	IN	ZONEMD	2018031900 1 1 (
										62e6cf51b02e54b9
										b5f967d547ce4313
										6792901f9f88e637
										493daaf401c92c27
										9dd10f0edb1c56f8
										080211f8480ee306 )
		`: "example.\t86400\tIN\tZONEMD\t2018031900 1 1 62e6cf51b02e54b9b5f967d547ce43136792901f9f88e637493daaf401c92c279dd10f0edb1c56f8080211f8480ee306",
		`example.	86400	IN	ZONEMD	2018031900 1 2 (
										08cfa1115c7b948c
										4163a901270395ea
										226a930cd2cbcf2f
										a9a5e6eb85f37c8a
										4e114d884e66f176
										eab121cb02db7d65
										2e0cc4827e7a3204
										f166b47e5613fd27 )
		`: "example.\t86400\tIN\tZONEMD\t2018031900 1 2 08cfa1115c7b948c4163a901270395ea226a930cd2cbcf2fa9a5e6eb85f37c8a4e114d884e66f176eab121cb02db7d652e0cc4827e7a3204f166b47e5613fd27",
		`example.	86400	IN	ZONEMD	2018031900 1 240 (
										e2d523f654b9422a
										96c5a8f44607bbee )
		`: "example.	86400	IN	ZONEMD	2018031900 1 240 e2d523f654b9422a96c5a8f44607bbee",
		`example.	86400	IN	ZONEMD	2018031900 241 1 (
										e1846540e33a9e41
										89792d18d5d131f6
										05fc283e )
		`: "example.	86400	IN	ZONEMD	2018031900 241 1 e1846540e33a9e4189792d18d5d131f605fc283e",
		// URI.ARPA zone
		`uri.arpa.		3600	IN		ZONEMD	2018100702 1 1 (
			0dbc3c4dbfd75777c12ca19c337854b1577799901307c482e9d91d5d15
			cd934d16319d98e30c4201cf25a1d5a0254960 )`: "uri.arpa.\t3600\tIN\tZONEMD\t2018100702 1 1 0dbc3c4dbfd75777c12ca19c337854b1577799901307c482e9d91d5d15cd934d16319d98e30c4201cf25a1d5a0254960",
		// ROOT-SERVERS.NET Zone
		`root-servers.net.     3600000 IN  ZONEMD  2018091100 1 1 (
			f1ca0ccd91bd5573d9f431c00ee0101b2545c97602be0a97
			8a3b11dbfc1c776d5b3e86ae3d973d6b5349ba7f04340f79 )
		`: "root-servers.net.\t3600000\tIN\tZONEMD\t2018091100 1 1 f1ca0ccd91bd5573d9f431c00ee0101b2545c97602be0a978a3b11dbfc1c776d5b3e86ae3d973d6b5349ba7f04340f79",
	}
	for i, o := range dt {
		rr, err := NewRR(i)
		if err != nil {
			t.Error("failed to parse RR: ", err)
			continue
		}
		if rr.String() != o {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", i, o, rr.String())
		}
	}
}

func TestParseIPSECKEY(t *testing.T) {
	dt := map[string]string{
		"ipseckey. 3600 IN IPSECKEY 10 0 2 . AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==":                                  "ipseckey.\t3600\tIN\tIPSECKEY\t10 0 2 . AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
		"ipseckey. 3600 IN IPSECKEY 10 1 2 1.2.3.4 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==":                            "ipseckey.\t3600\tIN\tIPSECKEY\t10 1 2 1.2.3.4 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
		"ipseckey. 3600 IN IPSECKEY 10 2 2 2001:470:30:84:e276:63ff:fe72:3900 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==": "ipseckey.\t3600\tIN\tIPSECKEY\t10 2 2 2001:470:30:84:e276:63ff:fe72:3900 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
		"ipseckey. 3600 IN IPSECKEY 10 3 2 ipseckey2. AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==":                         "ipseckey.\t3600\tIN\tIPSECKEY\t10 3 2 ipseckey2. AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
	}

	for i, o := range dt {
		rr := testRR(i).(*IPSECKEY)
		if s := rr.String(); s != o {
			t.Errorf("input %#v does not match expected output %#v", s, o)
		}
	}
}

func TestParseAMTRELAY(t *testing.T) {
	dt := map[string]string{
		"amtrelay. 3600 IN AMTRELAY 10 0 0 .":                                  "amtrelay.\t3600\tIN\tAMTRELAY\t10 0 0 .",
		"amtrelay. 3600 IN AMTRELAY 10 0 1 1.2.3.4":                            "amtrelay.\t3600\tIN\tAMTRELAY\t10 0 1 1.2.3.4",
		"amtrelay. 3600 IN AMTRELAY 10 1 2 2001:470:30:84:e276:63ff:fe72:3900": "amtrelay.\t3600\tIN\tAMTRELAY\t10 1 2 2001:470:30:84:e276:63ff:fe72:3900",
		"amtrelay. 3600 IN AMTRELAY 10 1 3 amtrelay2.":                         "amtrelay.\t3600\tIN\tAMTRELAY\t10 1 3 amtrelay2.",
	}

	for i, o := range dt {
		rr := testRR(i).(*AMTRELAY)
		if s := rr.String(); s != o {
			t.Errorf("input %#v does not match expected output %#v", s, o)
		}
	}
}

func TestParseOPENPGPKEY(t *testing.T) {
	dt := map[string]string{
		"2bd806c97f0e00af1a1fc3328fa763a9269723c8db8fac4f93af71db._openpgpkey 3600 IN OPENPGPKEY mDMEZCMu8xYJKwYBBAHaRw8BAQdAH4FTbN/H5SoMBl9Ez2cFQ1NuzymK894fq2ffsYDvRkG0EWFsaWNlQGV4YW1wbGUuY29tiJYEExYKAD4CGwMFCwkIBwMFFQoJCAsFFgIDAQACHgECF4AWIQRjw8oAQytQxDz5Q/Io7xpohfeBngUCZCMv5gUJAAk7ZgAKCRAo7xpohfeBnlmVAP9k0slIpLwddCD1bZ9qVjqzNcS743OIDny7XuH6x02L2wEAwxqAotO7/oUm0L4wyYR6hvGlhuGMSZXc9xMwZ1wVcA8=":     "2bd806c97f0e00af1a1fc3328fa763a9269723c8db8fac4f93af71db._openpgpkey.\t3600\tIN\tOPENPGPKEY\tmDMEZCMu8xYJKwYBBAHaRw8BAQdAH4FTbN/H5SoMBl9Ez2cFQ1NuzymK894fq2ffsYDvRkG0EWFsaWNlQGV4YW1wbGUuY29tiJYEExYKAD4CGwMFCwkIBwMFFQoJCAsFFgIDAQACHgECF4AWIQRjw8oAQytQxDz5Q/Io7xpohfeBngUCZCMv5gUJAAk7ZgAKCRAo7xpohfeBnlmVAP9k0slIpLwddCD1bZ9qVjqzNcS743OIDny7XuH6x02L2wEAwxqAotO7/oUm0L4wyYR6hvGlhuGMSZXc9xMwZ1wVcA8=",
		"2bb5bc4202aaecd48dcb54967c8e7f1b7574a436f04e0d15534b20e5._openpgpkey 3600 IN OPENPGPKEY mDMEZCMxgRYJKwYBBAHaRw8BAQdA/fgtlQjGflt2MUMWhRZRnH5Hg+BY9sQTeePmqqUs+lK0Fem6u+iho+WtkEBleGFtcGxlLmNvbYiWBBMWCgA+AhsDBQsJCAcDBRUKCQgLBRYCAwEAAh4BAheAFiEEIWsEkWx5wygGCb61+tJ3q3m88E0FAmQjMbMFCQAJOqwACgkQ+tJ3q3m88E0z4gEAtowKJMPefyV5YCW8VubgXK7Fa+hjwXOPSsHnEnJw9pUBAL+VZvNZv/VZvyGGMd31Yivqerzl6q+VIkZ6XffVb2AB": "2bb5bc4202aaecd48dcb54967c8e7f1b7574a436f04e0d15534b20e5._openpgpkey.\t3600\tIN\tOPENPGPKEY\tmDMEZCMxgRYJKwYBBAHaRw8BAQdA/fgtlQjGflt2MUMWhRZRnH5Hg+BY9sQTeePmqqUs+lK0Fem6u+iho+WtkEBleGFtcGxlLmNvbYiWBBMWCgA+AhsDBQsJCAcDBRUKCQgLBRYCAwEAAh4BAheAFiEEIWsEkWx5wygGCb61+tJ3q3m88E0FAmQjMbMFCQAJOqwACgkQ+tJ3q3m88E0z4gEAtowKJMPefyV5YCW8VubgXK7Fa+hjwXOPSsHnEnJw9pUBAL+VZvNZv/VZvyGGMd31Yivqerzl6q+VIkZ6XffVb2AB",
		"2bb5bc4202aaecd48dcb54967c8e7f1b7574a436f04e0d15534b20e5._openpgpkey 3600 IN OPENPGPKEY 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": "2bb5bc4202aaecd48dcb54967c8e7f1b7574a436f04e0d15534b20e5._openpgpkey.\t3600\tIN\tOPENPGPKEY\t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",
	}
	for i, o := range dt {
		rr := testRR(i).(*OPENPGPKEY)
		if s := rr.String(); s != o {
			t.Errorf("input %#v does not match expected output %#v", s, o)
		}
	}
}

func TestParseRRSIGAlgNames(t *testing.T) {
	tests := map[string]uint8{
		`miek.nl.  IN RRSIG SOA RSASHA1 2 43200 20140210031301 20140111031301 12051 miek.nl. MVZUyrYwq0iZhMFDDnVXD2Bvu7pcBoc=`:         RSASHA1,
		`miek.nl.  IN RRSIG SOA RSAMD5 2 43200 20140210031301 20140111031301 12051 miek.nl. MVZUyrYwq0iZhMFDDnVXD2Bvu7pcBoc=`:          RSAMD5,
		`miek.nl.  IN RRSIG SOA ECC-GOST 2 43200 20140210031301 20140111031301 12051 miek.nl. MVZUyrYwq0iZhMFDDnVXD2Bvu7pcBoc=`:        ECCGOST,
		`miek.nl.  IN RRSIG SOA ED448 2 43200 20140210031301 20140111031301 12051 miek.nl. MVZUyrYwq0iZhMFDDnVXD2Bvu7pcBoc=`:           ED448,
		`miek.nl.  IN RRSIG SOA ECDSAP256SHA256 2 43200 20140210031301 20140111031301 12051 miek.nl. MVZUyrYwq0iZhMFDDnVXD2Bvu7pcBoc=`: ECDSAP256SHA256,
		`miek.nl.  IN RRSIG SOA INDIRECT 2 43200 20140210031301 20140111031301 12051 miek.nl. MVZUyrYwq0iZhMFDDnVXD2Bvu7pcBoc=`:        INDIRECT,
		`miek.nl.  IN RRSIG SOA BLA 2 43200 20140210031301 20140111031301 12051 miek.nl. MVZUyrYwq0iZhMFDDnVXD2Bvu7pcBoc=`:             0,
		`miek.nl.  IN RRSIG SOA - 2 43200 20140210031301 20140111031301 12051 miek.nl. MVZUyrYwq0iZhMFDDnVXD2Bvu7pcBoc=`:               0,
	}
	for r, alg := range tests {
		rr, err := NewRR(r)
		if alg != 0 && err != nil {
			t.Error(err)
			continue
		}
		if alg != 0 && rr.(*RRSIG).Algorithm != alg {
			t.Errorf("expecting alg %d, got %d", alg, rr.(*RRSIG).Algorithm)
		}
	}
}
