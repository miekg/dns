package dns_test

import (
	"github.com/miekg/dns"
	"strings"
	"testing"
)

const TypeISBN uint16 = 0x0F01

// sorry DNS RFC writers, here we go with crazy idea test :)

type ISBN struct {
	x string // rdata with 10 or 13 numbers, dashes or spaces allowed
}

func (rd *ISBN) String() string              { return rd.x }
func (rd *ISBN) ReadText(txt []string) error { rd.x = strings.Join(txt, " "); return nil }

func NewISBN() dns.CustomRData { return &ISBN{""} }

var testrecord = "example.org.\t3600\tIN\tISBN\t12-3 456789-0-123"

func (rd *ISBN) Write(buf []byte) (int, error) {
	b := []byte(rd.x)
	n := copy(buf, b)
	if n != len(b) {
		return n, dns.ErrBuf
	}
	return n, nil
}

func (rd *ISBN) Read(buf []byte) (int, error) {
	rd.x = string(buf)
	return len(buf), nil
}

func (rd *ISBN) CopyTo(dest dns.CustomRData) error {
	isbn, ok := dest.(*ISBN)
	if !ok {
		return dns.ErrRdata
	}
	isbn.x = rd.x
	return nil
}

func TestCustomText(t *testing.T) {
	dns.RegisterCustomRR("ISBN", TypeISBN, NewISBN)
	defer dns.UnregisterCustomRR(TypeISBN)

	rr, err := dns.NewRR(testrecord)
	if err != nil {
		t.Fatal(err)
	}
	if rr.String() != testrecord {
		t.Errorf("Record string representation did not match original %#v != %#v", rr.String(), testrecord)
	} else {
		t.Log(rr.String())
	}
}

func TestCustomWire(t *testing.T) {
	dns.RegisterCustomRR("ISBN", TypeISBN, NewISBN)
	defer dns.UnregisterCustomRR(TypeISBN)

	rr, err := dns.NewRR(testrecord)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 100)
	off, err := dns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		t.Errorf("Got error packing ISBN: %s", err)
	}

	if ln := 40; ln != off {
		t.Errorf("Offset is not matching to length of custom RR: %d!=%d", off, ln)
	}

	rr1, off1, err := dns.UnpackRR(buf[:off], 0)
	if err != nil {
		t.Errorf("Got error unpacking ISBN: %s", err)
	}

	if off1 != off {
		t.Errorf("Offset after unpacking differs: %d != %d", off1, off)
	}

	if rr1.String() != testrecord {
		t.Errorf("Record string representation did not match original %#v != %#v", rr1.String(), testrecord)
	} else {
		t.Log(rr1.String())
	}
}

var smallzone = `$ORIGIN example.org.
@ SOA	sns.dns.icann.org. noc.dns.icann.org. 2014091518 7200 3600 1209600 3600
    A   1.2.3.4
ok ISBN 1231-92110-12
go ISBN 1231-92110-13
www ISBN 1231-92110-16
*  CNAME @
`

func TestCustomZoneParser(t *testing.T) {
	dns.RegisterCustomRR("ISBN", TypeISBN, NewISBN)
	defer dns.UnregisterCustomRR(TypeISBN)
	r := strings.NewReader(smallzone)
	for x := range dns.ParseZone(r, ".", "") {
		if err := x.Error; err != nil {
			t.Fatal(err)
		}
		t.Log(x.RR)
	}
}
