package dns

import (
	"testing"
)

func TestRadixName(t *testing.T) {
	tests := map[string]string{".": ".",
		"www.miek.nl.": ".nl.miek.www",
		"miek.nl.":     ".nl.miek",
		"mi\\.ek.nl.":  ".nl.mi\\.ek",
		`mi\\.ek.nl.`:  `.nl.ek.mi\\`,
		"":             "."}
	for i, o := range tests {
		t.Logf("%s %v\n", i, SplitLabels(i))
		if x := toRadixName(i); x != o {
			t.Logf("%s should convert to %s, not %s\n", i, o, x)
			t.Fail()
		}
	}
}

func TestInsert(t *testing.T) {
}
func TestRemove(t *testing.T) {
}
