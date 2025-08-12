package dns

import (
	"testing"
)

func TestReverseAddr(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{"192.0.2.42", "42.2.0.192.in-addr.arpa."},
		{"2001:0db8::cafe", "e.f.a.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."},
		{"::ffff:192.0.2.42", "a.2.2.0.0.0.0.c.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ReverseAddr(tc.input)
			if err != nil {
				t.Errorf("expected no error, got %s", err)
			}
			if got != tc.expect {
				t.Errorf("expected %q, got %q", tc.expect, got)
			}
		})
	}

	t.Run("invalid", func(t *testing.T) {
		got, err := ReverseAddr("192.not.an.ip")
		if err == nil {
			t.Errorf("expected error, got none")
		}
		if got != "" {
			t.Errorf("expected empty string, got %q", got)
		}
	})
}
