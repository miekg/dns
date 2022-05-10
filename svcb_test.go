package dns

import (
	"testing"
)

// This tests everything valid about SVCB but parsing.
// Parsing tests belong to parse_test.go.
func TestSVCB(t *testing.T) {
	svcbs := []struct {
		key  string
		data string
	}{
		{`mandatory`, `alpn,key65000`},
		{`alpn`, `h2,h2c`},
		{`port`, `499`},
		{`ipv4hint`, `3.4.3.2,1.1.1.1`},
		{`no-default-alpn`, ``},
		{`ipv6hint`, `1::4:4:4:4,1::3:3:3:3`},
		{`ech`, `YUdWc2JHOD0=`},
		{`dohpath`, `/dns-query{?dns}`},
		{`key65000`, `4\ 3`},
		{`key65001`, `\"\ `},
		{`key65002`, ``},
		{`key65003`, `=\"\"`},
		{`key65004`, `\254\ \ \030\000`},
	}

	for _, o := range svcbs {
		keyCode := svcbStringToKey(o.key)
		kv := makeSVCBKeyValue(keyCode)
		if kv == nil {
			t.Error("failed to parse svc key: ", o.key)
			continue
		}
		if kv.Key() != keyCode {
			t.Error("key constant is not in sync: ", keyCode)
			continue
		}
		err := kv.parse(o.data)
		if err != nil {
			t.Error("failed to parse svc pair: ", o.key)
			continue
		}
		b, err := kv.pack()
		if err != nil {
			t.Error("failed to pack value of svc pair: ", o.key, err)
			continue
		}
		if len(b) != int(kv.len()) {
			t.Errorf("expected packed svc value %s to be of length %d but got %d", o.key, int(kv.len()), len(b))
		}
		err = kv.unpack(b)
		if err != nil {
			t.Error("failed to unpack value of svc pair: ", o.key, err)
			continue
		}
		if str := kv.String(); str != o.data {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", o.key, o.data, str)
		}
	}
}

func TestDecodeBadSVCB(t *testing.T) {
	svcbs := []struct {
		key  SVCBKey
		data []byte
	}{
		{
			key:  SVCB_ALPN,
			data: []byte{3, 0, 0}, // There aren't three octets after 3
		},
		{
			key:  SVCB_NO_DEFAULT_ALPN,
			data: []byte{0},
		},
		{
			key:  SVCB_PORT,
			data: []byte{},
		},
		{
			key:  SVCB_IPV4HINT,
			data: []byte{0, 0, 0},
		},
		{
			key:  SVCB_IPV6HINT,
			data: []byte{0, 0, 0},
		},
	}
	for _, o := range svcbs {
		err := makeSVCBKeyValue(SVCBKey(o.key)).unpack(o.data)
		if err == nil {
			t.Error("accepted invalid svc value with key ", SVCBKey(o.key).String())
		}
	}
}

func TestPresentationSVCBAlpn(t *testing.T) {
	tests := map[string]string{
		"h2":                "h2",
		"http":              "http",
		"\xfa":              `\250`,
		"some\"other,chars": `some\"other\\\044chars`,
	}
	for input, want := range tests {
		e := new(SVCBAlpn)
		e.Alpn = []string{input}
		if e.String() != want {
			t.Errorf("improper conversion with String(), wanted %v got %v", want, e.String())
		}
	}
}

func TestSVCBAlpn(t *testing.T) {
	tests := map[string][]string{
		`. 1 IN SVCB 10 one.test. alpn=h2`:                                         {"h2"},
		`. 2 IN SVCB 20 two.test. alpn=h2,h3-19`:                                   {"h2", "h3-19"},
		`. 3 IN SVCB 30 three.test. alpn="f\\\\oo\\,bar,h2"`:                       {`f\oo,bar`, "h2"},
		`. 4 IN SVCB 40 four.test. alpn="part1,part2,part3\\,part4\\\\"`:           {"part1", "part2", `part3,part4\`},
		`. 5 IN SVCB 50 five.test. alpn=part1\,\p\a\r\t2\044part3\092,part4\092\\`: {"part1", "part2", `part3,part4\`},
	}
	for s, v := range tests {
		rr, err := NewRR(s)
		if err != nil {
			t.Error("failed to parse RR: ", err)
			continue
		}
		alpn := rr.(*SVCB).Value[0].(*SVCBAlpn).Alpn
		if len(v) != len(alpn) {
			t.Fatalf("parsing alpn failed, wanted %v got %v", v, alpn)
		}
		for i := range v {
			if v[i] != alpn[i] {
				t.Fatalf("parsing alpn failed, wanted %v got %v", v, alpn)
			}
		}
	}
}

func TestCompareSVCB(t *testing.T) {
	val1 := []SVCBKeyValue{
		&SVCBPort{
			Port: 117,
		},
		&SVCBAlpn{
			Alpn: []string{"h2", "h3"},
		},
	}
	val2 := []SVCBKeyValue{
		&SVCBAlpn{
			Alpn: []string{"h2", "h3"},
		},
		&SVCBPort{
			Port: 117,
		},
	}
	if !areSVCBPairArraysEqual(val1, val2) {
		t.Error("svcb pairs were compared without sorting")
	}
	if val1[0].Key() != SVCB_PORT || val2[0].Key() != SVCB_ALPN {
		t.Error("original svcb pairs were reordered during comparison")
	}
}
