// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"testing"
)

func TestTxtPack(t *testing.T) {
	// Test single entry TXT record
	rr, err := NewRR(`_raop._tcp.local. 60 IN TXT "single value"`)
	if err != nil {
		t.Error("Failed to parse single value TXT record", err)
	} else if rr, ok := rr.(*TXT); !ok {
		t.Error("Wrong type, record should be of type TXT")
	} else {
		if len(rr.Txt) != 1 {
			t.Error("Bad size of TXT value:", len(rr.Txt))
		} else if rr.Txt[0] != "single value" {
			t.Error("Bad single value")
		}
		if rr.String() != `_raop._tcp.local.	60	IN	TXT	"single value"` {
			t.Error("Bad representation of TXT record:", rr.String())
		}
		if rr.len() == 10 {
			t.Error("Bad size of serialized record:", rr.len())
		}
	}

	// Test multi entries TXT record
	rr, err = NewRR(`_raop._tcp.local. 60 IN TXT "a=1" "b=2" "c=3" "d=4"`)
	if err != nil {
		t.Error("Failed to parse multi-values TXT record", err)
	} else if rr, ok := rr.(*TXT); !ok {
		t.Error("Wrong type, record should be of type TXT")
	} else {
		if len(rr.Txt) != 4 {
			t.Error("Bad size of TXT multi-value:", len(rr.Txt))
		} else if rr.Txt[0] != "a=1" || rr.Txt[1] != "b=2" || rr.Txt[2] != "c=3" || rr.Txt[3] != "d=4" {
			t.Error("Bad values in TXT records")
		}
		if rr.String() != `_raop._tcp.local.	60	IN	TXT	"a=1" "b=2" "c=3" "d=4"` {
			t.Error("Bad representation of TXT multi value record:", rr.String())
		}
		if rr.len() != 43 {
			t.Error("Bad size of serialized multi value record:", rr.len())
		}
	}
}
