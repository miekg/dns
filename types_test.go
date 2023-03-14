package dns

import (
	"testing"
)

func TestCmToM(t *testing.T) {
	s := cmToM((0 << 4) + 0)
	if s != "0.00" {
		t.Error("0, 0")
	}

	s = cmToM((1 << 4) + 0)
	if s != "0.01" {
		t.Error("1, 0")
	}

	s = cmToM((3 << 4) + 1)
	if s != "0.30" {
		t.Error("3, 1")
	}

	s = cmToM((4 << 4) + 2)
	if s != "4" {
		t.Error("4, 2")
	}

	s = cmToM((5 << 4) + 3)
	if s != "50" {
		t.Error("5, 3")
	}

	s = cmToM((7 << 4) + 5)
	if s != "7000" {
		t.Error("7, 5")
	}

	s = cmToM((9 << 4) + 9)
	if s != "90000000" {
		t.Error("9, 9")
	}
}

func TestSplitN(t *testing.T) {
	xs := splitN("abc", 5)
	if len(xs) != 1 && xs[0] != "abc" {
		t.Errorf("failure to split abc")
	}

	s := ""
	for i := 0; i < 255; i++ {
		s += "a"
	}

	xs = splitN(s, 255)
	if len(xs) != 1 && xs[0] != s {
		t.Errorf("failure to split 255 char long string")
	}

	s += "b"
	xs = splitN(s, 255)
	if len(xs) != 2 || xs[1] != "b" {
		t.Errorf("failure to split 256 char long string: %d", len(xs))
	}

	// Make s longer
	for i := 0; i < 255; i++ {
		s += "a"
	}
	xs = splitN(s, 255)
	if len(xs) != 3 || xs[2] != "a" {
		t.Errorf("failure to split 510 char long string: %d", len(xs))
	}
}

func TestSprintName(t *testing.T) {
	tests := map[string]string{
		// Non-numeric escaping of special printable characters.
		" '@;()\"\\..example": `\ \'\@\;\(\)\"\..example`,
		"\\032\\039\\064\\059\\040\\041\\034\\046\\092.example": `\ \'\@\;\(\)\"\.\\.example`,

		// Numeric escaping of nonprintable characters.
		"\x00\x07\x09\x0a\x1f.\x7f\x80\xad\xef\xff":           `\000\007\009\010\031.\127\128\173\239\255`,
		"\\000\\007\\009\\010\\031.\\127\\128\\173\\239\\255": `\000\007\009\010\031.\127\128\173\239\255`,

		// No escaping of other printable characters, at least after a prior escape.
		";[a-zA-Z0-9_]+/*.~": `\;[a-zA-Z0-9_]+/*.~`,
		";\\091\\097\\045\\122\\065\\045\\090\\048\\045\\057\\095\\093\\043\\047\\042.\\126": `\;[a-zA-Z0-9_]+/*.~`,
		// "\\091\\097\\045\\122\\065\\045\\090\\048\\045\\057\\095\\093\\043\\047\\042.\\126": `[a-zA-Z0-9_]+/*.~`,

		// Incomplete "dangling" escapes are dropped regardless of prior escaping.
		"a\\": `a`,
		";\\": `\;`,

		// Escaped dots stay escaped regardless of prior escaping.
		"a\\.\\046.\\.\\046": `a\.\..\.\.`,
		"a\\046\\..\\046\\.": `a\.\..\.\.`,
	}
	for input, want := range tests {
		got := sprintName(input)
		if got != want {
			t.Errorf("input %q: expected %q, got %q", input, want, got)
		}
	}
}

func TestSprintTxtOctet(t *testing.T) {
	got := sprintTxtOctet("abc\\.def\007\"\127@\255\x05\xef\\")

	if want := "\"abc\\.def\\007\\\"W@\\173\\005\\239\""; got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestSprintTxt(t *testing.T) {
	got := sprintTxt([]string{
		"abc\\.def\007\"\127@\255\x05\xef\\",
		"example.com",
	})

	if want := "\"abc.def\\007\\\"W@\\173\\005\\239\" \"example.com\""; got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestRPStringer(t *testing.T) {
	rp := &RP{
		Hdr: RR_Header{
			Name:   "test.example.com.",
			Rrtype: TypeRP,
			Class:  ClassINET,
			Ttl:    600,
		},
		Mbox: "\x05first.example.com.",
		Txt:  "second.\x07example.com.",
	}

	const expected = "test.example.com.\t600\tIN\tRP\t\\005first.example.com. second.\\007example.com."
	if rp.String() != expected {
		t.Errorf("expected %v, got %v", expected, rp)
	}

	_, err := NewRR(rp.String())
	if err != nil {
		t.Fatalf("error parsing %q: %v", rp, err)
	}
}

func BenchmarkSprintName(b *testing.B) {
	for n := 0; n < b.N; n++ {
		got := sprintName("abc\\.def\007\"\127@\255\x05\xef\\")

		if want := "abc\\.def\\007\\\"W\\@\\173\\005\\239"; got != want {
			b.Fatalf("expected %q, got %q", want, got)
		}
	}
}

func BenchmarkSprintName_NoEscape(b *testing.B) {
	for n := 0; n < b.N; n++ {
		got := sprintName("large.example.com")

		if want := "large.example.com"; got != want {
			b.Fatalf("expected %q, got %q", want, got)
		}
	}
}

func BenchmarkSprintTxtOctet(b *testing.B) {
	for n := 0; n < b.N; n++ {
		got := sprintTxtOctet("abc\\.def\007\"\127@\255\x05\xef\\")

		if want := "\"abc\\.def\\007\\\"W@\\173\\005\\239\""; got != want {
			b.Fatalf("expected %q, got %q", want, got)
		}
	}
}

func BenchmarkSprintTxt(b *testing.B) {
	txt := []string{
		"abc\\.def\007\"\127@\255\x05\xef\\",
		"example.com",
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		got := sprintTxt(txt)

		if want := "\"abc.def\\007\\\"W@\\173\\005\\239\" \"example.com\""; got != want {
			b.Fatalf("expected %q, got %q", got, want)
		}
	}
}
