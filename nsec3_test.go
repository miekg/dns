// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"testing"
)

func TestPackNsec3(t *testing.T) {
	nsec3 := HashName("dnsex.nl.", SHA1, 0, "DEAD")
	if nsec3 != "ROCCJAE8BJJU7HN6T7NG3TNM8ACRS87J" {
		t.Logf("%v\n", nsec3)
		t.Fail()
	}

	nsec3 = HashName("a.b.c.example.org.", SHA1, 2, "DEAD")
	if nsec3 != "6LQ07OAHBTOOEU2R9ANI2AT70K5O0RCG" {
		t.Logf("%v\n", nsec3)
		t.Fail()
	}
}
