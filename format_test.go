package dns

import (
	"testing"
)

func TestFieldEmptyAData(t *testing.T) {
	rr := &A{
		Hdr:  RR_Header{},
		A: nil,
	}

	res := Field(rr, 1)
	if res != "" {
		t.Errorf("expected empty string but got %v", res)
	}
}

func TestFieldEmptyAAAAData(t *testing.T) {
	rr := &AAAA{
		Hdr:  RR_Header{},
		AAAA: nil,
	}

	res := Field(rr, 1)
	if res != "" {
		t.Errorf("expected empty string but got %v", res)
	}
}
