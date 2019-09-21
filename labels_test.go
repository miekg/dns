package dns

import (
	"strings"
	"testing"
)

func TestCompareDomainName(t *testing.T) {
	tests := []struct {
		s1, s2   string
		expected int
	}{
		{"www.miek.nl.", "miek.nl.", 2},
		{"miek.nl.", "www.bla.nl.", 1},
		{"www.bla.nl.", "nl.www.bla.", 0},
		{"www.miek.nl.", "nl.", 1},
		{"www.miek.nl.", "miek.nl.", 2},
		{"www.miek.nl.", ".", 0},
		{".", ".", 0},
		{"test.com.", "TEST.COM.", 2},
		{"a.b.c.d.e.f.", "a.b.c.d.e.", 0},
		{"a.b.c.d.e.", "a.b.c.d.e.", 5},
	}
	for _, x := range tests {
		if i := CompareDomainName(x.s1, x.s2); i != x.expected {
			t.Errorf("%s with %s should be %d got: %d", x.s1, x.s2, x.expected, i)
		}
	}
}

func TestSplit(t *testing.T) {
	splitter := map[string]int{
		"www.miek.nl.":     3,
		"www.miek.nl":      3,
		"www..miek.nl":     4,
		`www\.miek.nl.`:    2,
		`www\\.miek.nl.`:   3,
		`\\.miek.nl.`:      3,
		`\\\.miek.nl.`:     2,
		`\\\\.miek.nl.`:    3,
		`www.miek\\\\.nl.`: 3,
		`www.miek\\\.nl.`:  2,
		".":                0,
		"nl.":              1,
		"nl":               1,
		"com.":             1,
		".com.":            2,
	}
	for s, i := range splitter {
		if x := len(Split(s)); x != i {
			t.Errorf("labels should be %d, got %d: %s %v", i, x, s, Split(s))
		}
	}
}

func TestSplit2(t *testing.T) {
	splitter := map[string][]int{
		"www.miek.nl.": {0, 4, 9},
		"www.miek.nl":  {0, 4, 9},
		"nl":           {0},
	}
	for s, i := range splitter {
		x := Split(s)
		switch len(i) {
		case 1:
			if x[0] != i[0] {
				t.Errorf("labels should be %v, got %v: %s", i, x, s)
			}
		default:
			if x[0] != i[0] || x[1] != i[1] || x[2] != i[2] {
				t.Errorf("labels should be %v, got %v: %s", i, x, s)
			}
		}
	}
}

func TestPrevLabel(t *testing.T) {
	type prev struct {
		string
		int
	}
	prever := map[prev]int{
		{"www.miek.nl.", 0}: 12,
		{"www.miek.nl.", 1}: 9,
		{"www.miek.nl.", 2}: 4,

		{"www.miek.nl", 0}: 11,
		{"www.miek.nl", 1}: 9,
		{"www.miek.nl", 2}: 4,

		{"www.miek.nl.", 5}: 0,
		{"www.miek.nl", 5}:  0,

		{"www.miek.nl.", 3}: 0,
		{"www.miek.nl", 3}:  0,

		{"a.b.c.", 1}: 4,
		{"a.b.c", 1}:  4,
	}

	// make sure we are safe when the label  begins with a possibly escaped '.'
	for i := 1; i < 8; i++ {
		s := strings.Repeat(`\`, i) + "."
		prever[prev{s, 0}] = i + 1
	}

	for s, i := range prever {
		x, ok := PrevLabel(s.string, s.int)
		if i != x {
			t.Errorf("label should be %d, got %d, %t: preving %d, %s", i, x, ok, s.int, s.string)
		}
	}
}

func TestCountLabel(t *testing.T) {
	splitter := map[string]int{
		"www.miek.nl.": 3,
		"www.miek.nl":  3,
		"nl":           1,
		".":            0,
	}
	for s, i := range splitter {
		x := CountLabel(s)
		if x != i {
			t.Errorf("CountLabel should have %d, got %d", i, x)
		}
	}
}

func TestSplitDomainName(t *testing.T) {
	labels := map[string][]string{
		"miek.nl":       {"miek", "nl"},
		".":             nil,
		"www.miek.nl.":  {"www", "miek", "nl"},
		"www.miek.nl":   {"www", "miek", "nl"},
		"www..miek.nl":  {"www", "", "miek", "nl"},
		`www\.miek.nl`:  {`www\.miek`, "nl"},
		`www\\.miek.nl`: {`www\\`, "miek", "nl"},
		".www.miek.nl.": {"", "www", "miek", "nl"},
	}
domainLoop:
	for domain, splits := range labels {
		parts := SplitDomainName(domain)
		if len(parts) != len(splits) {
			t.Errorf("SplitDomainName returned %v for %s, expected %v", parts, domain, splits)
			continue domainLoop
		}
		for i := range parts {
			if parts[i] != splits[i] {
				t.Errorf("SplitDomainName returned %v for %s, expected %v", parts, domain, splits)
				continue domainLoop
			}
		}
	}
}

func TestIsDomainName(t *testing.T) {
	type ret struct {
		ok  bool
		lab int
	}
	names := map[string]*ret{
		"..":                     {false, 1},
		"@.":                     {true, 1},
		"www.example.com":        {true, 3},
		"www.e%ample.com":        {true, 3},
		"www.example.com.":       {true, 3},
		"mi\\k.nl.":              {true, 2},
		"mi\\k.nl":               {true, 2},
		longestDomain:            {true, 4},
		longestUnprintableDomain: {true, 4},
	}
	for d, ok := range names {
		l, k := IsDomainName(d)
		if ok.ok != k || ok.lab != l {
			t.Errorf(" got %v %d for %s ", k, l, d)
			t.Errorf("have %v %d for %s ", ok.ok, ok.lab, d)
		}
	}
}

func TestIsFqdnEscaped(t *testing.T) {
	for s, expect := range map[string]bool{
		".":                  true,
		"\\.":                false,
		"\\\\.":              true,
		"\\\\\\.":            false,
		"\\\\\\\\.":          true,
		"a.":                 true,
		"a\\.":               false,
		"a\\\\.":             true,
		"a\\\\\\.":           false,
		"ab.":                true,
		"ab\\.":              false,
		"ab\\\\.":            true,
		"ab\\\\\\.":          false,
		"..":                 true,
		".\\.":               false,
		".\\\\.":             true,
		".\\\\\\.":           false,
		"example.org.":       true,
		"example.org\\.":     false,
		"example.org\\\\.":   true,
		"example.org\\\\\\.": false,
		"example\\.org.":     true,
		"example\\\\.org.":   true,
		"example\\\\\\.org.": true,
		"\\example.org.":     true,
		"\\\\example.org.":   true,
		"\\\\\\example.org.": true,
	} {
		if got := IsFqdn(s); got != expect {
			t.Errorf("IsFqdn(%q) = %t, expected %t", s, got, expect)
		}
	}
}

func TestEqual(t *testing.T) {
	type testcase struct {
		a, b  string
		match bool
	}
	tests := []testcase{
		{"a", "a", true},
		{"a", "A", true},
		{"A", "a", true},
		{"A", "b", false},
		{"www.example.com.", "www.exAmpLe.com.", true},
		{"www.example.com.", "www.exAmpLe.org.", false},
	}
	for _, x := range tests {
		eq := equal(x.a, x.b)
		if eq != x.match {
			t.Errorf("%+v: want: %t got: %t", x, x.match, eq)
		}
	}
}

func BenchmarkSplitLabels(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Split("www.example.com.")
	}
}

func BenchmarkLenLabels(b *testing.B) {
	for i := 0; i < b.N; i++ {
		CountLabel("www.example.com.")
	}
}

func BenchmarkCompareDomainName(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		CompareDomainName("www.example.com.", "aa.example.com.")
	}
}

func BenchmarkIsSubDomain(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		IsSubDomain("www.example.com.", "aa.example.com.")
		IsSubDomain("example.com.", "aa.example.com.")
		IsSubDomain("miek.nl.", "aa.example.com.")
	}
}
