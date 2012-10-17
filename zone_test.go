package dns

import (
	"os"
	"testing"
)

func TestRadixName(t *testing.T) {
	tests := map[string]string{".": ".",
		"www.miek.nl.": ".nl.miek.www",
		"miek.nl.":     ".nl.miek",
		"mi\\.ek.nl.":  ".nl.mi\\.ek",
		`mi\\.ek.nl.`:  `.nl.ek.mi\\`,
		"":             "."}
	for i, o := range tests {
		t.Logf("%s %v\n", i, SplitLabels(i))
		if x := toRadixName(i); x != o {
			t.Logf("%s should convert to %s, not %s\n", i, o, x)
			t.Fail()
		}
	}
}

func TestApex(t *testing.T) {
	f, err := os.Open("t/miek.nl.signed_test")
	if err != nil {
		t.Logf("Failed to open zone file")
		t.Fail()
	}
	defer f.Close()
	z := NewZone("miek.nl.")
	to := ParseZone(f, "miek.nl.", "t/miek.nl.signed_test")
	for rr := range to {
		if rr.Error == nil {
			z.Insert(rr.RR)
		} else {
			t.Logf("Error %s\n", rr.Error.Error())
		}
	}
	apex := z.Apex()
	if apex == nil {
		t.Fatalf("Apex not found")
	}
	t.Logf("Apex found %s", apex.RR[TypeSOA][0].String())
	apex.RR[TypeSOA][0].(*RR_SOA).Serial++
	apex = z.Apex()
	t.Logf("Apex found %s", z.Apex().RR[TypeSOA][0].String())
}

func TestInsert(t *testing.T) {
	z := NewZone("miek.nl.")
	mx, _ := NewRR("foo.miek.nl. MX 10 mx.miek.nl.")
	z.Insert(mx)
	_, exact := z.Find("foo.miek.nl.")
	if exact != true {
		t.Fail() // insert broken?
	}
}

func TestRemove(t *testing.T) {
	z := NewZone("miek.nl.")
	mx, _ := NewRR("foo.miek.nl. MX 10 mx.miek.nl.")
	z.Insert(mx)
	zd, exact := z.Find("foo.miek.nl.")
	if exact != true {
		t.Fail() // insert broken?
	}
	z.Remove(mx)
	zd, exact = z.Find("foo.miek.nl.")
	if exact != false {
		println(zd.String())
		t.Errorf("zd(%s) exact(%s) still exists", zd, exact) // it should no longer be in the zone
	}
}
