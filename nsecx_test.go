// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"testing"
)

func TestPackNsec3(t *testing.T) {
	nsec3 := HashName("dnsex.nl.", SHA1, 0, "DEAD")
	if nsec3 != "ROCCJAE8BJJU7HN6T7NG3TNM8ACRS87J" {
		t.Logf("%v\n", nsec3)
		t.Fail()
	}

	nsec3 = HashName("a.b.c.example.org.", SHA1, 2, "DEAD")
	if nsec3 != "6LQ07OAHBTOOEU2R9ANI2AT70K5O0RCG" {
		t.Logf("%v\n", nsec3)
		t.Fail()
	}
}

func TestNsec3(t *testing.T) {
	// examples taken from .nl
	nsec3, _ := NewRR("39p91242oslggest5e6a7cci4iaeqvnk.nl. IN NSEC3 1 1 5 F10E9F7EA83FC8F3 39P99DCGG0MDLARTCRMCF6OFLLUL7PR6 NS DS RRSIG")
	if !nsec3.(*NSEC3).Cover("snasajsksasasa.nl.") { // 39p94jrinub66hnpem8qdpstrec86pg3
		t.Logf("39p94jrinub66hnpem8qdpstrec86pg3. should be covered by 39p91242oslggest5e6a7cci4iaeqvnk.nl. - 39P99DCGG0MDLARTCRMCF6OFLLUL7PR6")
		t.Fail()
	}
	nsec3, _ = NewRR("sk4e8fj94u78smusb40o1n0oltbblu2r.nl. IN NSEC3 1 1 5 F10E9F7EA83FC8F3 SK4F38CQ0ATIEI8MH3RGD0P5I4II6QAN NS SOA TXT RRSIG DNSKEY NSEC3PARAM")
	if !nsec3.(*NSEC3).Match("nl.") { // sk4e8fj94u78smusb40o1n0oltbblu2r.nl.
		t.Logf("sk4e8fj94u78smusb40o1n0oltbblu2r.nl. should match sk4e8fj94u78smusb40o1n0oltbblu2r.nl.")
		t.Fail()
	}
}

func newNSEC3(rr string) *NSEC3 {
	rr1, _ := NewRR(rr)
	return rr1.(*NSEC3)
}

func TestNsec3Proof(t *testing.T) {
	// denies existence of 'snasajsksasasa.nl. A'
	nsec3 := []RR{
		newNSEC3("sk4e8fj94u78smusb40o1n0oltbblu2r.nl. IN NSEC3 1 1 5 F10E9F7EA83FC8F3 SK4F38CQ0ATIEI8MH3RGD0P5I4II6QAN NS SOA TXT RRSIG DNSKEY NSEC3PARAM"),
		newNSEC3("39p91242oslggest5e6a7cci4iaeqvnk.nl. IN NSEC3 1 1 5 F10E9F7EA83FC8F3 39P99DCGG0MDLARTCRMCF6OFLLUL7PR6 NS DS RRSIG"),
		newNSEC3("t98kg1p1cjtdoc4ksb7g57jc9vulltcd.nl. IN NSEC3 1 1 5 F10E9F7EA83FC8F3 T98MULSKU3E499AGCTTRJK6H0L3E5T92 NS DS RRSIG")}

	err := VerifyNameError(nsec3, "snasajsksasasa.nl.", TypeA)
	if err != nil {
		t.Logf("Failed to validate NSEC3")
		t.Fail()
	}
	nsec3 = []RR{ // closest encloser can not be found, 1st NSEC3
		newNSEC3("bk4e8fj94u78smusb40o1n0oltbblu2r.nl. IN NSEC3 1 1 5 F10E9F7EA83FC8F3 SK4F38CQ0ATIEI8MH3RGD0P5I4II6QAN NS SOA TXT RRSIG DNSKEY NSEC3PARAM"),
		newNSEC3("39p91242oslggest5e6a7cci4iaeqvnk.nl. IN NSEC3 1 1 5 F10E9F7EA83FC8F3 39P99DCGG0MDLARTCRMCF6OFLLUL7PR6 NS DS RRSIG"),
		newNSEC3("t98kg1p1cjtdoc4ksb7g57jc9vulltcd.nl. IN NSEC3 1 1 5 F10E9F7EA83FC8F3 T98MULSKU3E499AGCTTRJK6H0L3E5T92 NS DS RRSIG")}

	err = VerifyNameError(nsec3, "snasajsksasasa.nl.", TypeA)
	if err == nil {
		t.Logf("Should fail validate NSEC3")
		t.Fail()
	}
	nsec3 = []RR{ // wildcard not covered, 3rd NSEC3
		newNSEC3("sk4e8fj94u78smusb40o1n0oltbblu2r.nl. IN NSEC3 1 1 5 F10E9F7EA83FC8F3 SK4F38CQ0ATIEI8MH3RGD0P5I4II6QAN NS SOA TXT RRSIG DNSKEY NSEC3PARAM"),
		newNSEC3("39p91242oslggest5e6a7cci4iaeqvnk.nl. IN NSEC3 1 1 5 F10E9F7EA83FC8F3 39P99DCGG0MDLARTCRMCF6OFLLUL7PR6 NS DS RRSIG"),
		newNSEC3("t98kg1p1cjtdoc4ksb7g57jc9vulltcd.nl. IN NSEC3 1 1 5 F10E9F7EA83FC8F3 T98LULSKU3E499AGCTTRJK6H0L3E5T92 NS DS RRSIG")}

	err = VerifyNameError(nsec3, "snasajsksasasa.nl.", TypeA)
	if err == nil {
		t.Logf("Should fail validate NSEC3")
		t.Fail()
	}
	nsec3 = []RR{ // nextcloser not covered, 2rd NSEC3
		newNSEC3("sk4e8fj94u78smusb40o1n0oltbblu2r.nl. IN NSEC3 1 1 5 F10E9F7EA83FC8F3 SK4F38CQ0ATIEI8MH3RGD0P5I4II6QAN NS SOA TXT RRSIG DNSKEY NSEC3PARAM"),
		newNSEC3("39p91242oslggest5e6a7cci4iaeqvnk.nl. IN NSEC3 1 1 5 F10E9F7EA83FC8F3 39P89DCGG0MDLARTCRMCF6OFLLUL7PR6 NS DS RRSIG"),
		newNSEC3("t98kg1p1cjtdoc4ksb7g57jc9vulltcd.nl. IN NSEC3 1 1 5 F10E9F7EA83FC8F3 T98LULSKU3E499AGCTTRJK6H0L3E5T92 NS DS RRSIG")}

	err = VerifyNameError(nsec3, "snasajsksasasa.nl.", TypeA)
	if err == nil {
		t.Logf("Should fail validate NSEC3")
		t.Fail()
	}
}
