package dns

import "testing"

func TestFuzzString(t *testing.T) {
	testcases := []string{"", " MINFO ", "	RP ", "	NSEC 0 0", "	\" NSEC 0 0\"", "  \" MINFO \"",
		";a ", ";a����������",
		"	NSAP O ", "  NSAP N ",
		" TYPE4 TYPE6a789a3bc0045c8a5fb42c7d1bd998f5444 IN 9579b47d46817afbd17273e6",
//		"   HIP 0 e e @  . .",
	}
	for i, tc := range testcases {
		rr, err := NewRR(tc)
		if err == nil {
			// rr can still be nil because we can (for instance) just parse a comment
			if rr == nil {
				continue
			}
			t.Fatalf("parsed mailformed RR %d: %s", i, rr.String)
		}
	}
}
