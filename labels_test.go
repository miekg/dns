// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"testing"
)

func TestCompareLabels(t *testing.T) {
	s1 := "www.miek.nl."
	s2 := "miek.nl."
	s3 := "www.bla.nl."
	s4 := "nl.www.bla."
	s5 := "nl"

	if CompareLabels(s1, s2) != 2 {
		t.Logf("%s with %s should be %d", s1, s2, 2)
		t.Fail()
	}
	if CompareLabels(s1, s3) != 1 {
		t.Logf("%s with %s should be %d", s1, s3, 1)
		t.Fail()
	}
	if CompareLabels(s3, s4) != 0 {
		t.Logf("%s with %s should be %d", s3, s4, 0)
		t.Fail()
	}
	if CompareLabels(s1, s5) != 1 {
		t.Logf("%s with %s should be %d", s1, s5, 1)
		t.Fail()
	}
	if CompareLabels(s1, ".") != 0 {
		t.Logf("%s with %s should be %d", s1, s5, 0)
		t.Fail()
	}
	if CompareLabels(".", ".") != 0 {
		t.Logf("%s with %s should be %d", ".", ".", 0)
		t.Fail()
	}
}

func TestSplit(t *testing.T) {
	splitter := map[string]int{
		"www.miek.nl.":   3,
		"www.miek.nl":    3,
		`www\.miek.nl.`:  2,
		`www\\.miek.nl.`: 3,
		".":              0,
	}
	for s, i := range splitter {
		if x := len(Split(s)); x != i {
			t.Logf("Labels should be %d, got %d: %s\n", i, x, s)
			t.Fail()
		}
	}
}

func TestLenLabels(t *testing.T) {
	labels := map[string]int{
		"miek.nl":       2,
		".":             0,
		"www.miek.nl.":  3,
		"www.miek.nl":   3,
		"www..miek.nl":  4,
		`www\.miek.nl`:  2,
		`www\\.miek.nl`: 3,
	}
	for owner, lab := range labels {
		if l := LenLabels(owner); l != lab {
			t.Logf("%s should have %d labels, got %d\n", owner, lab, l)
			t.Fail()
		}
	}
}
