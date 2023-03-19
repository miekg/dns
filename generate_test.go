package dns

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateRangeGuard(t *testing.T) {
	tmpdir := t.TempDir()

	for i := 0; i <= 1; i++ {
		path := filepath.Join(tmpdir, fmt.Sprintf("%04d.conf", i))
		data := []byte(fmt.Sprintf("dhcp-%04d A 10.0.0.%d", i, i))

		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("could not create tmpfile for test: %v", err)
		}
	}

	tests := [...]struct {
		zone string
		fail bool
	}{
		{`@ IN SOA ns.test. hostmaster.test. ( 1 8h 2h 7d 1d )
$GENERATE 0-1 dhcp-${0,4,d} A 10.0.0.$
`, false},
		{`@ IN SOA ns.test. hostmaster.test. ( 1 8h 2h 7d 1d )
$GENERATE 0-1 dhcp-${0,0,x} A 10.0.0.$
`, false},
		{`@ IN SOA ns.test. hostmaster.test. ( 1 8h 2h 7d 1d )
$GENERATE 128-129 dhcp-${-128,4,d} A 10.0.0.$
`, false},
		{`@ IN SOA ns.test. hostmaster.test. ( 1 8h 2h 7d 1d )
$GENERATE 128-129 dhcp-${-129,4,d} A 10.0.0.$
`, true},
		{`@ IN SOA ns.test. hostmaster.test. ( 1 8h 2h 7d 1d )
$GENERATE 0-2 dhcp-${2147483647,4,d} A 10.0.0.$
`, true},
		{`@ IN SOA ns.test. hostmaster.test. ( 1 8h 2h 7d 1d )
$GENERATE 0-1 dhcp-${2147483646,4,d} A 10.0.0.$
`, false},
		{`@ IN SOA ns.test. hostmaster.test. ( 1 8h 2h 7d 1d )
$GENERATE 0-1/step dhcp-${0,4,d} A 10.0.0.$
`, true},
		{`@ IN SOA ns.test. hostmaster.test. ( 1 8h 2h 7d 1d )
$GENERATE 0-1/ dhcp-${0,4,d} A 10.0.0.$
`, true},
		{`@ IN SOA ns.test. hostmaster.test. ( 1 8h 2h 7d 1d )
$GENERATE 0-10/2 dhcp-${0,4,d} A 10.0.0.$
`, false},
		{`@ IN SOA ns.test. hostmaster.test. ( 1 8h 2h 7d 1d )
$GENERATE 0-1/0 dhcp-${0,4,d} A 10.0.0.$
`, true},
		{`@ IN SOA ns.test. hostmaster.test. ( 1 8h 2h 7d 1d )
$GENERATE 0-1 $$INCLUDE ` + tmpdir + string(filepath.Separator) + `${0,4,d}.conf
`, false},
		{`@ IN SOA ns.test. hostmaster.test. ( 1 8h 2h 7d 1d )
$GENERATE 0-1 dhcp-${0,4,d} A 10.0.0.$
$GENERATE 0-2 dhcp-${0,4,d} A 10.1.0.$
`, false},
	}

	for i := range tests {
		z := NewZoneParser(strings.NewReader(tests[i].zone), "test.", "test")
		z.SetIncludeAllowed(true)

		for _, ok := z.Next(); ok; _, ok = z.Next() {
		}

		err := z.Err()
		if err != nil && !tests[i].fail {
			t.Errorf("expected \n\n%s\nto be parsed, but got %v", tests[i].zone, err)
		} else if err == nil && tests[i].fail {
			t.Errorf("expected \n\n%s\nto fail, but got no error", tests[i].zone)
		}
	}
}

func TestGenerateIncludeDepth(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "dns")
	if err != nil {
		t.Fatalf("could not create tmpfile for test: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	zone := `@ IN SOA ns.test. hostmaster.test. ( 1 8h 2h 7d 1d )
$GENERATE 0-1 $$INCLUDE ` + tmpfile.Name() + `
`
	if _, err := tmpfile.WriteString(zone); err != nil {
		t.Fatalf("could not write to tmpfile for test: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("could not close tmpfile for test: %v", err)
	}

	zp := NewZoneParser(strings.NewReader(zone), ".", tmpfile.Name())
	zp.SetIncludeAllowed(true)

	for _, ok := zp.Next(); ok; _, ok = zp.Next() {
	}

	const expected = "too deeply nested $INCLUDE"
	if err := zp.Err(); err == nil || !strings.Contains(err.Error(), expected) {
		t.Errorf("expected error to include %q, got %v", expected, err)
	}
}

func TestGenerateIncludeDisallowed(t *testing.T) {
	const zone = `@ IN SOA ns.test. hostmaster.test. ( 1 8h 2h 7d 1d )
$GENERATE 0-1 $$INCLUDE test.conf
`
	zp := NewZoneParser(strings.NewReader(zone), ".", "")

	for _, ok := zp.Next(); ok; _, ok = zp.Next() {
	}

	const expected = "$INCLUDE directive not allowed"
	if err := zp.Err(); err == nil || !strings.Contains(err.Error(), expected) {
		t.Errorf("expected error to include %q, got %v", expected, err)
	}
}

func TestGenerateSurfacesErrors(t *testing.T) {
	const zone = `@ IN SOA ns.test. hostmaster.test. ( 1 8h 2h 7d 1d )
$GENERATE 0-1 dhcp-${0,4,dd} A 10.0.0.$
`
	zp := NewZoneParser(strings.NewReader(zone), ".", "test")

	for _, ok := zp.Next(); ok; _, ok = zp.Next() {
	}

	const expected = `test: dns: bad base in $GENERATE: "${0,4,dd}" at line: 2:20`
	if err := zp.Err(); err == nil || err.Error() != expected {
		t.Errorf("expected specific error, wanted %q, got %v", expected, err)
	}
}

func TestGenerateSurfacesLexerErrors(t *testing.T) {
	const zone = `@ IN SOA ns.test. hostmaster.test. ( 1 8h 2h 7d 1d )
$GENERATE 0-1 dhcp-${0,4,d} A 10.0.0.$ )
`
	zp := NewZoneParser(strings.NewReader(zone), ".", "test")

	for _, ok := zp.Next(); ok; _, ok = zp.Next() {
	}

	const expected = `test: dns: bad data in $GENERATE directive: "extra closing brace" at line: 2:40`
	if err := zp.Err(); err == nil || err.Error() != expected {
		t.Errorf("expected specific error, wanted %q, got %v", expected, err)
	}
}

func TestGenerateModToPrintf(t *testing.T) {
	tests := []struct {
		mod        string
		wantFmt    string
		wantOffset int64
		wantErr    bool
	}{
		{"0,0,d", "%d", 0, false},
		{"0,0", "%d", 0, false},
		{"0", "%d", 0, false},
		{"3,2,d", "%02d", 3, false},
		{"3,2", "%02d", 3, false},
		{"3", "%d", 3, false},
		{"0,0,o", "%o", 0, false},
		{"0,0,x", "%x", 0, false},
		{"0,0,X", "%X", 0, false},
		{"0,0,z", "", 0, true},
		{"0,0,0,d", "", 0, true},
		{"-100,0,d", "%d", -100, false},
	}
	for _, test := range tests {
		gotFmt, gotOffset, errMsg := modToPrintf(test.mod)
		switch {
		case errMsg != "" && !test.wantErr:
			t.Errorf("modToPrintf(%q) - expected empty-error, but got %v", test.mod, errMsg)
		case errMsg == "" && test.wantErr:
			t.Errorf("modToPrintf(%q) - expected error, but got empty-error", test.mod)
		case gotFmt != test.wantFmt:
			t.Errorf("modToPrintf(%q) - expected format %q, but got %q", test.mod, test.wantFmt, gotFmt)
		case gotOffset != test.wantOffset:
			t.Errorf("modToPrintf(%q) - expected offset %d, but got %d", test.mod, test.wantOffset, gotOffset)
		}
	}
}

func BenchmarkGenerate(b *testing.B) {
	const zone = `@ IN SOA ns.test. hostmaster.test. ( 1 8h 2h 7d 1d )
$GENERATE 32-158 dhcp-${-32,4,d} A 10.0.0.$
`

	for n := 0; n < b.N; n++ {
		zp := NewZoneParser(strings.NewReader(zone), ".", "")

		for _, ok := zp.Next(); ok; _, ok = zp.Next() {
		}

		if err := zp.Err(); err != nil {
			b.Fatal(err)
		}
	}
}

func TestCrasherString(t *testing.T) {
	tests := []struct {
		in  string
		err string
	}{
		{"$GENERATE 0-300103\"$$GENERATE 2-2", "bad range in $GENERATE"},
		{"$GENERATE 0-5414137360", "bad range in $GENERATE"},
		{"$GENERATE       11522-3668518066406258", "bad range in $GENERATE"},
		{"$GENERATE 0-200\"(;00000000000000\n$$GENERATE 0-0", "dns: garbage after $GENERATE range: \"\\\"\" at line: 1:16"},
		{"$GENERATE 6-2048 $$GENERATE 6-036160 $$$$ORIGIN \\$", `dns: nested $GENERATE directive not allowed: "6-036160" at line: 1:19`},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			_, err := NewRR(tc.in)
			if err == nil {
				t.Errorf("Expecting error for crasher line %s", tc.in)
			}
			if !strings.Contains(err.Error(), tc.err) {
				t.Errorf("Expecting error %s, got %s", tc.err, err.Error())
			}
		})
	}
}
