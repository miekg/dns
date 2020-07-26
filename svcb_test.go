package dns

import (
	"strings"
	"testing"
)

// This tests everything valid about SVCB but parsing.
// Parsing tests belong to parse_test.go.
func TestSVCB(t *testing.T) {
	svcbs := map[string]string{
		`mandatory=key65000,alpn`:        `key65000,alpn`,
		`alpn=h2,h2c`:                    `h2,h2c`,
		`port="499"`:                     `499`,
		`ipv4hint=3.4.3.2,1.1.1.1`:       `3.4.3.2,1.1.1.1`,
		`no-default-alpn=`:               ``,
		`ipv6hint=1::4:4:4:4,1::3:3:3:3`: `1::4:4:4:4,1::3:3:3:3`,
		`echconfig=Mw==`:                 `Mw==`,
		`key65000=4\ 3`:                  `4\ 3`,
		`key65001="\" "`:                 `\"\ `,
		`key65002=""`:                    ``,
		`key65003==\"\"`:                 `=\"\"`,
		`key65004=\254\032\030\000`:      `\254\ \030\000`,
	}

	for s, o := range svcbs {
		var key, value string
		idx := strings.IndexByte(s, '=')
		if idx < 0 {
			key = s
		} else {
			value = s[idx+1:]
			if len(value) > 1 && value[0] == '"' {
				value = value[1 : len(value)-1]
			}
			key = s[0:idx]
		}
		keyCode := svcbStringToKey(key)
		kv := makeSVCBKeyValue(keyCode)
		if kv == nil {
			t.Error("failed to parse svc key: ", key)
			continue
		}
		if kv.Key() != keyCode {
			t.Error("key constant is not in sync: ", keyCode)
			continue
		}
		err := kv.parse(value)
		if err != nil {
			t.Error("failed to parse svc pair: ", s)
			continue
		}
		b, err := kv.pack()
		if err != nil {
			t.Error("failed to pack value of svc pair: ", s, err)
			continue
		}
		if len(b) != int(kv.len()) {
			t.Errorf("expected packed svc value %s to be of length %d but got %d", s, int(kv.len()), len(b))
		}
		err = kv.unpack(b)
		if err != nil {
			t.Error("failed to unpack value of svc pair: ", s, err)
			continue
		}
		if str := kv.String(); str != o {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", s, o, str)
		}
	}
}

func TestDecodeBadSVCB(t *testing.T) {
	svcbs := map[SVCBKey][][]byte{
		SVCB_ALPN: {
			{3, 0, 0}, // There aren't three octets after 3
		},
		SVCB_NO_DEFAULT_ALPN: {
			{0},
		},
		SVCB_PORT: {
			{},
		},
		SVCB_IPV4HINT: {
			{0, 0, 0},
		},
		SVCB_IPV6HINT: {
			{0, 0, 0},
		},
	}
	for s, o := range svcbs {
		key_value := makeSVCBKeyValue(SVCBKey(s))
		for _, e := range o {
			err := key_value.unpack(e)
			if err == nil {
				t.Error("accepted invalid svc value with key ", SVCBKey(s).string())
			}
		}
	}
}
