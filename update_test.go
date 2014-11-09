package dns

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

