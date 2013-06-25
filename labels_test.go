// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"testing"
)

func TestCompareDomainName(t *testing.T) {
	s1 := "www.miek.nl."
	s2 := "miek.nl."
	s3 := "www.bla.nl."
	s4 := "nl.www.bla."
	s5 := "nl"

	if CompareDomainName(s1, s2) != 2 {
		t.Logf("%s with %s should be %d", s1, s2, 2)
		t.Fail()
	}
	if CompareDomainName(s1, s3) != 1 {
		t.Logf("%s with %s should be %d", s1, s3, 1)
		t.Fail()
	}
	if CompareDomainName(s3, s4) != 0 {
		t.Logf("%s with %s should be %d", s3, s4, 0)
		t.Fail()
	}
	if CompareDomainName(s1, s5) != 1 {
		t.Logf("%s with %s should be %d", s1, s5, 1)
		t.Fail()
	}
	if CompareDomainName(s1, ".") != 0 {
		t.Logf("%s with %s should be %d", s1, s5, 0)
		t.Fail()
	}
	if CompareDomainName(".", ".") != 0 {
		t.Logf("%s with %s should be %d", ".", ".", 0)
		t.Fail()
	}
}

func TestSplit(t *testing.T) {
	splitter := map[string]int{
		"www.miek.nl.":   3,
		"www.miek.nl":    3,
		"www..miek.nl":   4,
		`www\.miek.nl.`:  2,
		`www\\.miek.nl.`: 3,
		".":              0,
		"nl.":            1,
		"nl":             1,
		"com.":           1,
		".com.":          2,
	}
	for s, i := range splitter {
		if x := len(Split(s)); x != i {
			t.Logf("Labels should be %d, got %d: %s %v\n", i, x, s, Split(s))
			t.Fail()
		} else {
			t.Logf("%s %v\n", s, Split(s))
		}
	}
}

func TestSplitDomainName(t *testing.T) {
	labels := map[string][]string{
		"miek.nl":       []string{"miek", "nl"},
		".":             nil,
		"www.miek.nl.":  []string{"www", "miek", "nl"},
		"www.miek.nl":   []string{"www", "miek", "nl"},
		"www..miek.nl":  []string{"www", "", "miek", "nl"},
		`www\.miek.nl`:  []string{`www\.miek`, "nl"},
		`www\\.miek.nl`: []string{`www\\`, "miek", "nl"},
	}
domainLoop:
	for domain, splits := range labels {
		parts := SplitDomainName(domain)
		if len(parts) != len(splits) {
			t.Logf("SplitDomainName returned %v for %s, expected %v", parts, domain, splits)
			t.Fail()
			continue domainLoop
		}
		for i := range parts {
			if parts[i] != splits[i] {
				t.Logf("SplitDomainName returned %v for %s, expected %v", parts, domain, splits)
				t.Fail()
				continue domainLoop
			}
		}
	}
}

func BenchmarkSplitLabels(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Split("www.example.com")
	}
}

func BenchmarkLenLabels(b *testing.B) {
	for i := 0; i < b.N; i++ {
		CountLabel("www.example.com")
	}
}

func BenchmarkCompareLabels(b *testing.B) {
	for i := 0; i < b.N; i++ {
		CompareDomainName("www.example.com", "aa.example.com")
	}
}

func BenchmarkIsSubDomain(b *testing.B) {
	for i := 0; i < b.N; i++ {
		IsSubDomain("www.example.com", "aa.example.com")
		IsSubDomain("example.com", "aa.example.com")
		IsSubDomain("miek.nl", "aa.example.com")
	}
}
