package dns

import (
	"strings"
	"testing"
)

var testcases = [][2]string{
	{"a", "a"},
	{"A-B", "a-b"},
	{"AbC", "abc"},
	{"я", "xn--41a"},
	{"zя", "xn--z-0ub"},
	{"ЯZ", "xn--z-zub"},
	{"إختبار", "xn--kgbechtv"},
	{"آزمایشی", "xn--hgbk6aj7f53bba"},
	{"测试", "xn--0zwm56d"},
	{"測試", "xn--g6w251d"},
	{"Испытание", "xn--80akhbyknj4f"},
	{"परीक्षा", "xn--11b5bs3a9aj6g"},
	{"δοκιμή", "xn--jxalpdlp"},
	{"테스트", "xn--9t4b11yi5a"},
	{"טעסט", "xn--deba0ad"},
	{"テスト", "xn--zckzah"},
	{"பரிட்சை", "xn--hlcj6aya9esc7a"},
}

func TestEncodePunycode(t *testing.T) {
	for _, tst := range testcases {
		enc := encode_punycode([]byte(tst[0]))
		if string(enc) != tst[1] {
			t.Errorf("%s encodeded as %s but should be %s", tst[0], enc, tst[1])
		}
		dec := decode_punycode([]byte(tst[1]))
		if string(dec) != strings.ToLower(tst[0]) {
			t.Errorf("%s decoded as %s but should be %s", tst[1], dec, strings.ToLower(tst[0]))
		}
	}
}
