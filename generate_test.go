package dns

import (
	"testing"
	"strings"
)

func TestGenerateRangeGuard(t *testing.T) {
	var tests = [...]struct {
		zone string
		fail bool
	}{{
		`@ IN SOA ns.test. hostmaster.test. ( 1 8h 2h 7d 1d )
$GENERATE 0-1 dhcp-${0,4,d} A 10.0.0.$
`, false},{
		`@ IN SOA ns.test. hostmaster.test. ( 1 8h 2h 7d 1d )
$GENERATE 128-129 dhcp-${-128,4,d} A 10.0.0.$
`, false},{
		`@ IN SOA ns.test. hostmaster.test. ( 1 8h 2h 7d 1d )
$GENERATE 128-129 dhcp-${-129,4,d} A 10.0.0.$
`, true},{
		`@ IN SOA ns.test. hostmaster.test. ( 1 8h 2h 7d 1d )
$GENERATE 0-2 dhcp-${2147483647,4,d} A 10.0.0.$
`, true},{
		`@ IN SOA ns.test. hostmaster.test. ( 1 8h 2h 7d 1d )
$GENERATE 0-1 dhcp-${2147483646,4,d} A 10.0.0.$
`, false},
	}
Outer:
	for i := range tests {
		for tok := range ParseZone(strings.NewReader(tests[i].zone), "test.", "test") {
			if tok.Error != nil {
				if !tests[i].fail {
					t.Errorf("expected \n\n%s\nto be parsed, but got %v", tests[i].zone, tok.Error)
				}
				continue Outer
			}
		}
		if tests[i].fail {
			t.Errorf("expected \n\n%s\nto fail, but got no error", tests[i].zone)
		}
	}
}

func TestGenerateModToPrintf(t *testing.T) {
	tests := []struct {
		mod        string
		wantFmt    string
		wantOffset int
		wantErr    bool
	}{
		{"0,0,d", "%0d", 0, false},
		{"0,0", "%0d", 0, false},
		{"0", "%0d", 0, false},
		{"3,2,d", "%02d", 3, false},
		{"3,2", "%02d", 3, false},
		{"3", "%0d", 3, false},
		{"0,0,o", "%0o", 0, false},
		{"0,0,x", "%0x", 0, false},
		{"0,0,X", "%0X", 0, false},
		{"0,0,z", "", 0, true},
		{"0,0,0,d", "", 0, true},
		{"-100,0,d", "%0d", -100, false},
	}
	for _, test := range tests {
		gotFmt, gotOffset, err := modToPrintf(test.mod)
		switch {
		case err != nil && !test.wantErr:
			t.Errorf("modToPrintf(%q) - expected nil-error, but got %v", test.mod, err)
		case err == nil && test.wantErr:
			t.Errorf("modToPrintf(%q) - expected error, but got nil-error", test.mod)
		case gotFmt != test.wantFmt:
			t.Errorf("modToPrintf(%q) - expected format %q, but got %q", test.mod, test.wantFmt, gotFmt)
		case gotOffset != test.wantOffset:
			t.Errorf("modToPrintf(%q) - expected offset %d, but got %d", test.mod, test.wantOffset, gotOffset)
		}
	}
}
