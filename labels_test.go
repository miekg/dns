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
	if CompareLabels(".", ".") != 0 {
		t.Logf("%s with %s should be %d", ".", ".", 0)
		t.Fail()
	}
}

func TestSplitLabels(t *testing.T) {
	s1 := "www.miek.nl."
	s2 := "www.miek.nl"
	s3 := `www\.miek.nl.`
	s4 := `www\\.miek.nl.`

	if len(SplitLabels(s1)) != 3 {
		t.Logf("Labels should be 3, %s\n", s1)
		t.Fail()
	}
	if len(SplitLabels(s2)) != 3 {
		t.Logf("Labels should be 3, %s\n", s2)
		t.Fail()
	}
	if len(SplitLabels(s3)) != 2 {
		t.Logf("Labels should be 2, %s\n", s3)
		t.Fail()
	}
	if len(SplitLabels(s4)) != 3 {
		t.Logf("Labels should be 3, %s\n", s4)
		t.Fail()
	}
	if len(SplitLabels(".")) != 0 {
		t.Logf("Labels should be 0, %s\n", ".")
		t.Fail()
	}
}
