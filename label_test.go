// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"testing"
)

func TestLenLabels(t *testing.T) {
	labels := map[string]int{
		"miek.nl": 2,
		".":       0,
		"www.miek.nl.": 3,
		"www.miek.nl": 3,
		"www..miek.nl": 4,
		`www\.miek.nl`: 2,
		`www\\.miek.nl`: 3,
	}
	for owner, lab := range labels {
		if l := LenLabels2(owner); l != lab {
			t.Logf("%s should have %d labels, got %d\n", owner, lab, l)
			t.Fail()
		}
	}
}
