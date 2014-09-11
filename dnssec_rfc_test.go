// Copyright 2014 CloudFlare. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"reflect"
	"testing"
)

// Here the test vectors from the relevant RFCs are checked.

// rfc6605 6.1
func TestRFC6605P256(t *testing.T) {
	exDNSKEY := `example.net. 3600 IN DNSKEY 257 3 13 (
                 GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb
                 krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA== )`
	exPriv := `Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ=`
	rrDNSKEY, err := NewRR(exDNSKEY)
	if err != nil {
		t.Fatal(err.Error())
	}
	priv, err := rrDNSKEY.(*DNSKEY).NewPrivateKey(exPriv)
	if err != nil {
		t.Fatal(err.Error())
	}

	exDS := `example.net. 3600 IN DS 55648 13 2 (
             b4c8c1fe2e7477127b27115656ad6256f424625bf5c1
             e2770ce6d6e37df61d17 )`
	rrDS, err := NewRR(exDS)
	if err != nil {
		t.Fatal(err.Error())
	}
	ourDS := rrDNSKEY.(*DNSKEY).ToDS(SHA256)
	if !reflect.DeepEqual(ourDS, rrDS.(*DS)) {
		t.Errorf("DS record differs:\n%v\n%v\n", ourDS, rrDS.(*DS))
	}

	exA := `www.example.net. 3600 IN A 192.0.2.1`
	exRRSIG := `www.example.net. 3600 IN RRSIG A 13 3 3600 (
                20100909100439 20100812100439 55648 example.net.
                qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXA
                yGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw== )`
	rrA, err := NewRR(exA)
	if err != nil {
		t.Fatal(err.Error())
	}
	rrRRSIG, err := NewRR(exRRSIG)
	if err != nil {
		t.Fatal(err.Error())
	}
	if err = rrRRSIG.(*RRSIG).Verify(rrDNSKEY.(*DNSKEY), []RR{rrA}); err != nil {
		t.Errorf("Failure to validate the spec RRSIG: %v", err)
	}

	ourRRSIG := &RRSIG{
		Hdr: RR_Header{
			Ttl: rrA.Header().Ttl,
		},
		KeyTag:     rrDNSKEY.(*DNSKEY).KeyTag(),
		SignerName: rrDNSKEY.(*DNSKEY).Hdr.Name,
		Algorithm:  rrDNSKEY.(*DNSKEY).Algorithm,
	}
	ourRRSIG.Expiration, _ = StringToTime("20100909100439")
	ourRRSIG.Inception, _ = StringToTime("20100812100439")
	err = ourRRSIG.Sign(priv, []RR{rrA})
	if err != nil {
		t.Fatal(err.Error())
	}

	if err = ourRRSIG.Verify(rrDNSKEY.(*DNSKEY), []RR{rrA}); err != nil {
		t.Errorf("Failure to validate our RRSIG: %v", err)
	}

	// Signatures are randomized
	rrRRSIG.(*RRSIG).Signature = ""
	ourRRSIG.Signature = ""
	if !reflect.DeepEqual(ourRRSIG, rrRRSIG.(*RRSIG)) {
		t.Fatalf("RRSIG record differs:\n%v\n%v\n", ourRRSIG, rrRRSIG.(*RRSIG))
	}
}

// rfc6605 6.2
func TestRFC6605P384(t *testing.T) {
	exDNSKEY := `example.net. 3600 IN DNSKEY 257 3 14 (
                 xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1
                 w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8
                 /uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40 )`
	exPriv := `Private-key-format: v1.2
Algorithm: 14 (ECDSAP384SHA384)
PrivateKey: WURgWHCcYIYUPWgeLmiPY2DJJk02vgrmTfitxgqcL4vwW7BOrbawVmVe0d9V94SR`
	rrDNSKEY, err := NewRR(exDNSKEY)
	if err != nil {
		t.Fatal(err.Error())
	}
	priv, err := rrDNSKEY.(*DNSKEY).NewPrivateKey(exPriv)
	if err != nil {
		t.Fatal(err.Error())
	}

	exDS := `example.net. 3600 IN DS 10771 14 4 (
           72d7b62976ce06438e9c0bf319013cf801f09ecc84b8
           d7e9495f27e305c6a9b0563a9b5f4d288405c3008a94
           6df983d6 )`
	rrDS, err := NewRR(exDS)
	if err != nil {
		t.Fatal(err.Error())
	}
	ourDS := rrDNSKEY.(*DNSKEY).ToDS(SHA384)
	if !reflect.DeepEqual(ourDS, rrDS.(*DS)) {
		t.Fatalf("DS record differs:\n%v\n%v\n", ourDS, rrDS.(*DS))
	}

	exA := `www.example.net. 3600 IN A 192.0.2.1`
	exRRSIG := `www.example.net. 3600 IN RRSIG A 14 3 3600 (
           20100909102025 20100812102025 10771 example.net.
           /L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP
           95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuz
           WTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm )`
	rrA, err := NewRR(exA)
	if err != nil {
		t.Fatal(err.Error())
	}
	rrRRSIG, err := NewRR(exRRSIG)
	if err != nil {
		t.Fatal(err.Error())
	}
	if err = rrRRSIG.(*RRSIG).Verify(rrDNSKEY.(*DNSKEY), []RR{rrA}); err != nil {
		t.Errorf("Failure to validate the spec RRSIG: %v", err)
	}

	ourRRSIG := &RRSIG{
		Hdr: RR_Header{
			Ttl: rrA.Header().Ttl,
		},
		KeyTag:     rrDNSKEY.(*DNSKEY).KeyTag(),
		SignerName: rrDNSKEY.(*DNSKEY).Hdr.Name,
		Algorithm:  rrDNSKEY.(*DNSKEY).Algorithm,
	}
	ourRRSIG.Expiration, _ = StringToTime("20100909102025")
	ourRRSIG.Inception, _ = StringToTime("20100812102025")
	err = ourRRSIG.Sign(priv, []RR{rrA})
	if err != nil {
		t.Fatal(err.Error())
	}

	if err = ourRRSIG.Verify(rrDNSKEY.(*DNSKEY), []RR{rrA}); err != nil {
		t.Errorf("Failure to validate our RRSIG: %v", err)
	}

	// Signatures are randomized
	rrRRSIG.(*RRSIG).Signature = ""
	ourRRSIG.Signature = ""
	if !reflect.DeepEqual(ourRRSIG, rrRRSIG.(*RRSIG)) {
		t.Fatalf("RRSIG record differs:\n%v\n%v\n", ourRRSIG, rrRRSIG.(*RRSIG))
	}
}
