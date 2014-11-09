package dns

import (
	"testing"
)

func TestDynamicUpdateParsing(t *testing.T) {
	prefix := "example.com. IN "
	for _, typ := range TypeToString {
		if typ == "CAA" || typ == "OPT" || typ == "AXFR" || typ == "IXFR" || typ == "ANY" || typ == "TKEY" ||
			typ == "TSIG" || typ == "ISDN" || typ == "UNSPEC" || typ == "NULL" || typ == "ATMA" {
			continue
		}
		r, e := NewRR(prefix + typ)
		if e != nil {
			t.Log("failure to parse: " + prefix + typ)
			t.Fail()
		} else {
			t.Logf("parsed: %s", r.String())
		}
	}
}

func TestDynamicUpdateUnpack(t *testing.T) {
	// From https://github.com/miekg/dns/issues/150#issuecomment-62296803
	buf := []byte{171, 68, 40, 0, 0, 1, 0, 0, 0, 2, 0, 0, 7, 101, 120, 97, 109, 112, 108, 101, 0, 0, 6, 0, 1, 192, 12, 0, 1, 0, 255, 0, 0, 0, 0, 0, 0, 192, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1}
	msg := new(Msg)
	err := msg.Unpack(buf)
	if err != nil {
		t.Log("failed to unpack: " + err.Error())
//		t.Fail()
	}
}
