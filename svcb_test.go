package dns

import (
	"strings"
	"testing"
)

// This tests everything valid about SVCB but parsing.
// Parsing tests belong to parse_test.go.
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
		keyCode := SvcStringToKey(key)
		keyValue := makeSvcKeyValue(keyCode)
		if keyValue == nil {
			t.Error("failed to parse svc key: ", key)
			continue
		}
		if keyValue.Key() != keyCode {
			t.Error("key constant is not in sync: ", keyCode)
			continue
		}
		err := keyValue.read(val)
		if err != nil {
			t.Error("failed to parse svc pair: ", s)
			continue
		}
		b, err := keyValue.pack()
		if err != nil {
			t.Error("failed to pack value of svc pair: ", s, err)
			continue
		}
		if len(b) != int(keyValue.len()) {
			t.Errorf("expected packed svc value %s to be of length %d but got %d", s, int(keyValue.len()), len(b))
		}
		err = keyValue.unpack(b)
		if err != nil {
			t.Error("failed to unpack value of svc pair: ", s, err)
			continue
		}
		if str := keyValue.String(); str != o {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", s, o, str)
		}
	}
}

func TestDecodeBadSVCB(t *testing.T) {
	svcbs := map[int][][]byte{
		SVC_ALPN: {
			{3, 0, 0}, // There aren't three octets after 3
		},
		SVC_NO_DEFAULT_ALPN: {
			{0},
		},
		SVC_PORT: {
			{},
		},
		SVC_IPV4HINT: {
			{0, 0, 0},
		},
		SVC_IPV6HINT: {
			{0, 0, 0},
		},
	}
	for s, o := range svcbs {
		key_value := makeSvcKeyValue(uint16(s))
		for _, e := range o {
			err := key_value.unpack(e)
			if err == nil {
				t.Error("accepted invalid svc value with key ", SvcKeyToString(uint16(s)))
			}
		}
	}
}
