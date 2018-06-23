package dns

import (
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
}

func TestParseZoneInclude(t *testing.T) {

	tmpfile, err := ioutil.TempFile("", "dns")
	if err != nil {
		t.Fatalf("could not create tmpfile for test: %s", err)
	}

	if _, err := tmpfile.WriteString("foo\tIN\tA\t127.0.0.1"); err != nil {
		t.Fatalf("unable to write content to tmpfile %q: %s", tmpfile.Name(), err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("could not close tmpfile %q: %s", tmpfile.Name(), err)
	}

	zone := "$ORIGIN example.org.\n$INCLUDE " + tmpfile.Name()

	tok := ParseZone(strings.NewReader(zone), "", "")
	for x := range tok {
		if x.Error != nil {
			t.Fatalf("expected no error, but got %s", x.Error)
		}
		if x.RR.Header().Name != "foo.example.org." {
			t.Fatalf("expected %s, but got %s", "foo.example.org.", x.RR.Header().Name)
		}
	}

	os.Remove(tmpfile.Name())

	tok = ParseZone(strings.NewReader(zone), "", "")
	for x := range tok {
		if x.Error == nil {
			t.Fatalf("expected first token to contain an error but it didn't")
		}
		if !strings.Contains(x.Error.Error(), "failed to open") ||
			!strings.Contains(x.Error.Error(), tmpfile.Name()) {
			t.Fatalf(`expected error to contain: "failed to open" and %q but got: %s`, tmpfile.Name(), x.Error)
		}
	}
}
