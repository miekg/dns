package dns

import "testing"

func TestFuzzString(t *testing.T) {
	testcases := []string{"", " MINFO ", "	RP ", "	NSEC 0 0", "	\" NSEC 0 0\"", "  \" MINFO \""}
	for i, tc := range testcases {
		rr, err := NewRR(tc)
		if err == nil {
			if tc == "" { // special case...
				continue
			}
			t.Fatalf("parsed mailformed RR %d: %s", i, rr.String)
		}
	}
}
