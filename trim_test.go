package dns

import "testing"

func TestTrim(t *testing.T) {
	in := []struct {
		s      string
		origin string
		out    string
	}{
		{".", ".", "@"},
		{"example.org.", ".", "example.org"},
		{"example.org.", "org.", "example"},
		{"example.org.", "example.org.", "@"},
		{"example.org.", "www.example.org.", "example.org."},
	}

	for _, tc := range in {
		out := trim(tc.s, tc.origin)
		if out != tc.out {
			t.Errorf("expected %s, got %s", out, tc.out)
		}
	}
}

func TestRelativeString(t *testing.T) {
	x, _ := NewRR(`example.org. IN TXT "blaat"`)
	xs := x.(*TXT).RelativeString("org.")
	if xs != "example\t3600\tIN\tTXT\t\"blaat\"" {
		t.Errorf("expected %s, got %s", xs, "example\t3600\tIN\tTXT\t\"blaat\"")
	}
	xs = x.(*TXT).RelativeString("example.org.")
	if xs != "@\t3600\tIN\tTXT\t\"blaat\"" {
		t.Errorf("expected %s, got %s", xs, "@\t3600\tIN\tTXT\t\"blaat\"")
	}
}
