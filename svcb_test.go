package dns

import (
	"strings"
	"testing"
)

func TestSVCB(t *testing.T) {
	header := `example.com. 3600 IN SVCB `
	svcbs := map[string]string{
		`0 cloudflare.com.`:                  `0 cloudflare.com.`,
		`1 . alpn=h2,h2c`:                    `alpn="h2,h2c"`,
		`1 . esniconfig=b`:                   `esniconfig="b"`,
		`1 . port="499"`:                     `port="499"`,
		`1 . ipv4hint=3.4.3.2,1.1.1.1`:       `ipv4hint="3.4.3.2,1.1.1.1"`,
		`1 . no-default-alpn=`:               `no-default-alpn=""`,
		`1 . ipv6hint=1::4:4:4:4,1::3:3:3:3`: `ipv6hint="1::4:4:4:4,1::3:3:3:3"`,
		`1 . esniconfig=Mw==`:                `esniconfig="Mw=="`,
		`1 . key65000=4\ 3`:                  `key65000="4\ 3"`,
		`1 . key65001="\" "`:                 `key65001="\"\ "`,
		`1 . key65002`:                       `key65002=""`,
		`1 . key65003=`:                      `key65003=""`,
		`1 . key65004=""`:                    `key65004=""`,
		`1 . key65005==`:                     `key65005="="`,
		`1 . key65006==\"\"`:                 `key65006="=\"\""`,
		`1 . key65007=\254`:                  `key65007="\254"`,
		`1 . key65007=\032`:                  `key65007="\ "`,
	}
	for s, o := range svcbs {
		rr, err := NewRR(header + s)
		if err != nil {
			t.Error("failed to parse RR: ", err)
			continue
		}
		if !strings.HasSuffix(rr.String(), o) {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", s, header+o, header+rr.String())
		}
		//e, err := rr.SVCB.Value[0].pack()
		/*	o := new(SVCB)
			o.parse(c, o)
			if err != nil {
				t.Errorf("failed to pack valid RR: `%s' with error `%s'", rr.String, err)
			}*/
	}
}
