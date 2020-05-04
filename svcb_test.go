package dns

import (
	"strings"
	"testing"
)

// This tests everything about SVCB but the parser.
// Parser tests belong to parse_test.go.
func TestSVCB(t *testing.T) {
	svcbs := map[string]string{
		`alpn=h2,h2c`:                    `h2,h2c`,
		`port="499"`:                     `499`,
		`ipv4hint=3.4.3.2,1.1.1.1`:       `3.4.3.2,1.1.1.1`,
		`no-default-alpn=`:               ``,
		`ipv6hint=1::4:4:4:4,1::3:3:3:3`: `1::4:4:4:4,1::3:3:3:3`,
		`esniconfig=Mw==`:                `Mw==`,
		`key65000=4\ 3`:                  `4\ 3`,
		`key65001="\" "`:                 `\"\ `,
		`key65002=""`:                    ``,
		`key65003==\"\"`:                 `=\"\"`,
		`key65004=\254\032\030\000`:      `\254\ \030\000`,
	}

	for s, o := range svcbs {
		key := ""
		val := ""
		idx := strings.IndexByte(s, '=')
		if idx == -1 {
			key = s
		} else {
			val = s[idx+1:]
			if len(val) > 1 && val[0] == '"' {
				val = val[1 : len(val)-1]
			}
			key = s[0:idx]
		}
		key_value := makeSvcKeyValue(SvcStringToKey(key))
		if key_value == nil {
			t.Error("failed to parse svc key: ", key)
			continue
		}
		err := key_value.read(val)
		if err != nil {
			t.Error("failed to parse svc pair: ", s)
			continue
		}
		b, err := key_value.pack()
		if err != nil {
			t.Error("failed to pack value of svc pair: ", s, err)
			continue
		}
		if len(b) != int(key_value.len()) {
			t.Errorf("expected packed svc value %s to be of length %d but got %d", s, int(key_value.len()), len(b))
		}
		err = key_value.unpack(b)
		if err != nil {
			t.Error("failed to unpack value of svc pair: ", s, err)
			continue
		}
		if str := key_value.String(); str != o {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", s, o, str)
		}
	}
}
