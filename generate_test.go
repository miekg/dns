package dns

import (
	"testing"
)

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
