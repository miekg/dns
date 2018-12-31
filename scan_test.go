package dns

import (
	"io"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"testing"
)

func TestParseZoneGenerate(t *testing.T) {
	zone := "$ORIGIN example.org.\n$GENERATE 10-12 foo${2,3,d} IN A 127.0.0.$"

	wantRRs := []RR{
		&A{Hdr: RR_Header{Name: "foo012.example.org."}, A: net.ParseIP("127.0.0.10")},
		&A{Hdr: RR_Header{Name: "foo013.example.org."}, A: net.ParseIP("127.0.0.11")},
		&A{Hdr: RR_Header{Name: "foo014.example.org."}, A: net.ParseIP("127.0.0.12")},
	}
	wantIdx := 0

	tok := ParseZone(strings.NewReader(zone), "", "")
	for x := range tok {
		if wantIdx >= len(wantRRs) {
			t.Fatalf("expected %d RRs, but got more", len(wantRRs))
		}
		if x.Error != nil {
			t.Fatalf("expected no error, but got %s", x.Error)
		}
		if got, want := x.RR.Header().Name, wantRRs[wantIdx].Header().Name; got != want {
			t.Fatalf("expected name %s, but got %s", want, got)
		}
		a, ok := x.RR.(*A)
		if !ok {
			t.Fatalf("expected *A RR, but got %T", x.RR)
		}
		if got, want := a.A, wantRRs[wantIdx].(*A).A; !got.Equal(want) {
			t.Fatalf("expected A with IP %v, but got %v", got, want)
		}
		wantIdx++
	}

	if wantIdx != len(wantRRs) {
		t.Errorf("too few records, expected %d, got %d", len(wantRRs), wantIdx)
	}
}

func TestParseZoneInclude(t *testing.T) {

	tmpfile, err := ioutil.TempFile("", "dns")
	if err != nil {
		t.Fatalf("could not create tmpfile for test: %s", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.WriteString("foo\tIN\tA\t127.0.0.1"); err != nil {
		t.Fatalf("unable to write content to tmpfile %q: %s", tmpfile.Name(), err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("could not close tmpfile %q: %s", tmpfile.Name(), err)
	}

	zone := "$ORIGIN example.org.\n$INCLUDE " + tmpfile.Name() + "\nbar\tIN\tA\t127.0.0.2"

	var got int
	tok := ParseZone(strings.NewReader(zone), "", "")
	for x := range tok {
		if x.Error != nil {
			t.Fatalf("expected no error, but got %s", x.Error)
		}
		switch x.RR.Header().Name {
		case "foo.example.org.", "bar.example.org.":
		default:
			t.Fatalf("expected foo.example.org. or bar.example.org., but got %s", x.RR.Header().Name)
		}
		got++
	}

	if expected := 2; got != expected {
		t.Errorf("failed to parse zone after include, expected %d records, got %d", expected, got)
	}

	os.Remove(tmpfile.Name())

	tok = ParseZone(strings.NewReader(zone), "", "")
	for x := range tok {
		if x.Error == nil {
			t.Fatalf("expected first token to contain an error but it didn't")
		}
		if !strings.Contains(x.Error.Error(), "failed to open") ||
			!strings.Contains(x.Error.Error(), tmpfile.Name()) ||
			!strings.Contains(x.Error.Error(), "no such file or directory") {
			t.Fatalf(`expected error to contain: "failed to open", %q and "no such file or directory" but got: %s`,
				tmpfile.Name(), x.Error)
		}
	}
}

func TestZoneParserIncludeDisallowed(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "dns")
	if err != nil {
		t.Fatalf("could not create tmpfile for test: %s", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.WriteString("foo\tIN\tA\t127.0.0.1"); err != nil {
		t.Fatalf("unable to write content to tmpfile %q: %s", tmpfile.Name(), err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("could not close tmpfile %q: %s", tmpfile.Name(), err)
	}

	zp := NewZoneParser(strings.NewReader("$INCLUDE "+tmpfile.Name()), "example.org.", "")

	for _, ok := zp.Next(); ok; _, ok = zp.Next() {
	}

	const expect = "$INCLUDE directive not allowed"
	if err := zp.Err(); err == nil || !strings.Contains(err.Error(), expect) {
		t.Errorf("expected error to contain %q, got %v", expect, err)
	}
}

func TestParseTA(t *testing.T) {
	rr, err := NewRR(` Ta 0 0 0`)
	if err != nil {
		t.Fatalf("expected no error, but got %s", err)
	}
	if rr == nil {
		t.Fatal(`expected a normal RR, but got nil`)
	}
}

func TestZLexerExpect(t *testing.T) {
	rr, err := NewRR("example.com. 42 IN SOA ns1.example.com.\"hostmaster.example.com.\"1 86400 60 86400 3600")
	if err == nil {
		t.Errorf("expected error, got record: %v", rr)
	} else if expect := `dns: bad SOA Mbox: "unexpected type 0x8 lexer token, wanted bitmask 0x4" at line: 1:40`; err.Error() != expect {
		t.Errorf("expected error %q, got %q", expect, err.Error())
	}
}

func TestZLexerUncheckedError(t *testing.T) {
	rr, err := NewRR("nl. IN NSEC3PARAM 1 0 5\"\"")
	if err == nil {
		t.Errorf("expected error, got record: %v", rr)
	} else if expect := `dns: error parsing RR: "unexpected type 0x8 lexer token, wanted bitmask 0x4" at line: 1:24`; err.Error() != expect {
		t.Errorf("expected error %q, got %q", expect, err.Error())
	}
}

var errTestReadError = &Error{"test error"}

type errReader struct{}

func (errReader) Read(p []byte) (int, error) { return 0, errTestReadError }

func TestParseZoneReadError(t *testing.T) {
	rr, err := ReadRR(errReader{}, "")
	if err == nil || !strings.Contains(err.Error(), errTestReadError.Error()) {
		t.Errorf("expected error to contain %q, but got %v", errTestReadError, err)
	}
	if rr != nil {
		t.Errorf("expected a nil RR, but got %v", rr)
	}
}

func BenchmarkNewRR(b *testing.B) {
	const name1 = "12345678901234567890123456789012345.12345678.123."
	const s = name1 + " 3600 IN MX 10 " + name1

	for n := 0; n < b.N; n++ {
		_, err := NewRR(s)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadRR(b *testing.B) {
	const name1 = "12345678901234567890123456789012345.12345678.123."
	const s = name1 + " 3600 IN MX 10 " + name1 + "\n"

	for n := 0; n < b.N; n++ {
		r := struct{ io.Reader }{strings.NewReader(s)}
		// r is now only an io.Reader and won't benefit from the
		// io.ByteReader special-case in zlexer.Next.

		_, err := ReadRR(r, "")
		if err != nil {
			b.Fatal(err)
		}
	}
}

const benchZone = `
foo. IN A 10.0.0.1 ; this is comment 1
foo. IN A (
	10.0.0.2 ; this is comment 2
)
; this is comment 3
foo. IN A 10.0.0.3
foo. IN A ( 10.0.0.4 ); this is comment 4

foo. IN A 10.0.0.5
; this is comment 5

foo. IN A 10.0.0.6

foo. IN DNSKEY 256 3 5 AwEAAb+8l ; this is comment 6
foo. IN NSEC miek.nl. TXT RRSIG NSEC; this is comment 7
foo. IN TXT "THIS IS TEXT MAN"; this is comment 8
`

func BenchmarkParseZone(b *testing.B) {
	for n := 0; n < b.N; n++ {
		for tok := range ParseZone(strings.NewReader(benchZone), "example.org.", "") {
			if tok.Error != nil {
				b.Fatal(tok.Error)
			}
		}
	}
}

func BenchmarkZoneParser(b *testing.B) {
	for n := 0; n < b.N; n++ {
		zp := NewZoneParser(strings.NewReader(benchZone), "example.org.", "")

		for _, ok := zp.Next(); ok; _, ok = zp.Next() {
		}

		if err := zp.Err(); err != nil {
			b.Fatal(err)
		}
	}
}
