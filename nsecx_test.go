package dns

import (
	"fmt"
	"testing"
)

func TestPackNsec3(t *testing.T) {
	nsec3 := HashName("dnsex.nl.", SHA1, 0, "DEAD")
	if nsec3 != "ROCCJAE8BJJU7HN6T7NG3TNM8ACRS87J" {
		t.Error(nsec3)
	}

	nsec3 = HashName("a.b.c.example.org.", SHA1, 2, "DEAD")
	if nsec3 != "6LQ07OAHBTOOEU2R9ANI2AT70K5O0RCG" {
		t.Error(nsec3)
	}
}

func TestNsec3(t *testing.T) {
	nsec3, _ = NewRR("sk4e8fj94u78smusb40o1n0oltbblu2r.nl. IN NSEC3 1 1 5 F10E9F7EA83FC8F3 SK4F38CQ0ATIEI8MH3RGD0P5I4II6QAN NS SOA TXT RRSIG DNSKEY NSEC3PARAM")
	if !nsec3.(*NSEC3).Match("nl.") { // sk4e8fj94u78smusb40o1n0oltbblu2r.nl.
		t.Error("sk4e8fj94u78smusb40o1n0oltbblu2r.nl. should match sk4e8fj94u78smusb40o1n0oltbblu2r.nl.")
	}

	for _, tc := range []struct {
		rr     *NSEC3
		name   string
		covers bool
	}{
		// good
		{
			rr: &NSEC3{
				Hdr:        RR_Header{Name: "39p91242oslggest5e6a7cci4iaeqvnk.nl."},
				Hash:       1,
				Flags:      1,
				Iterations: 5,
				Salt:       "F10E9F7EA83FC8F3",
				NextDomain: "39P99DCGG0MDLARTCRMCF6OFLLUL7PR6",
			},
			name:   "snasajsksasasa.nl.",
			covers: true,
		},
		{
			rr: &NSEC3{
				Hdr:        RR_Header{Name: "3v62ulr0nre83v0rja2vjgtlif9v6rab.com."},
				Hash:       1,
				Flags:      1,
				Iterations: 5,
				Salt:       "F10E9F7EA83FC8F3",
				NextDomain: "2N1TB3VAIRUOBL6RKDVII42N9TFMIALP",
			},
			name:   "csd.com.",
			covers: true,
		},
		// bad
		{ // out of zone
			rr: &NSEC3{
				Hdr:        RR_Header{Name: "39p91242oslggest5e6a7cci4iaeqvnk.nl."},
				Hash:       1,
				Flags:      1,
				Iterations: 5,
				Salt:       "F10E9F7EA83FC8F3",
				NextDomain: "39P99DCGG0MDLARTCRMCF6OFLLUL7PR6",
			},
			name:   "asd.com.",
			covers: false,
		},
		{ // empty interval
			rr: &NSEC3{
				Hdr:        RR_Header{Name: "2n1tb3vairuobl6rkdvii42n9tfmialp.com."},
				Hash:       1,
				Flags:      1,
				Iterations: 5,
				Salt:       "F10E9F7EA83FC8F3",
				NextDomain: "2N1TB3VAIRUOBL6RKDVII42N9TFMIALP",
			},
			name:   "asd.com.",
			covers: false,
		},
	} {
		fmt.Println("test")
		covers := tc.rr.Cover(tc.name)
		if tc.covers != covers {
			t.Fatalf("Cover failed for %s: expected %t, got %t [record: %s]", tc.name, tc.covers, covers, tc.rr)
		}
	}
	fmt.Println("bsd.com.", HashName("bsd.com.", 1, 5, "F10E9F7EA83FC8F3"))
}
