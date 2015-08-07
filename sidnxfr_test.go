// +build SIDN

// These tests run against servers maintained by SIDN labs, see:
// https://workbench.sidnlabs.nl/
//
// Tests will only be run if the SIDN build tag is provided to `go test`.
// Specific configurations can be tested by providing a regex to `go test`.
//
// Eg:
//     go test -tags SIDN -run "AXFR_.*_MD5"
//     go test -tags SIDN -run "AXFR_NSD4_.*"
//

package dns

import (
	"testing"
	"time"
)

func TestAXFR_NSD3_NONE(t *testing.T)   { testAXFR(t, "nsd", "") }
func TestAXFR_NSD3_MD5(t *testing.T)    { testAXFR(t, "nsd", HmacMD5) }
func TestAXFR_NSD3_SHA1(t *testing.T)   { testAXFR(t, "nsd", HmacSHA1) }
func TestAXFR_NSD3_SHA256(t *testing.T) { testAXFR(t, "nsd", HmacSHA256) }

func TestAXFR_NSD4_NONE(t *testing.T)   { testAXFR(t, "nsd4", "") }
func TestAXFR_NSD4_MD5(t *testing.T)    { testAXFR(t, "nsd4", HmacMD5) }
func TestAXFR_NSD4_SHA1(t *testing.T)   { testAXFR(t, "nsd4", HmacSHA1) }
func TestAXFR_NSD4_SHA256(t *testing.T) { testAXFR(t, "nsd4", HmacSHA256) }

func TestAXFR_BIND9_NONE(t *testing.T)   { testAXFR(t, "bind9", "") }
func TestAXFR_BIND9_MD5(t *testing.T)    { testAXFR(t, "bind9", HmacMD5) }
func TestAXFR_BIND9_SHA1(t *testing.T)   { testAXFR(t, "bind9", HmacSHA1) }
func TestAXFR_BIND9_SHA256(t *testing.T) { testAXFR(t, "bind9", HmacSHA256) }

func TestAXFR_KNOT_NONE(t *testing.T)   { testAXFR(t, "knot", "") }
func TestAXFR_KNOT_MD5(t *testing.T)    { testAXFR(t, "knot", HmacMD5) }
func TestAXFR_KNOT_SHA1(t *testing.T)   { testAXFR(t, "knot", HmacSHA1) }
func TestAXFR_KNOT_SHA256(t *testing.T) { testAXFR(t, "knot", HmacSHA256) }

func TestAXFR_POWERDNS_NONE(t *testing.T)   { testAXFR(t, "powerdns", "") }
func TestAXFR_POWERDNS_MD5(t *testing.T)    { testAXFR(t, "powerdns", HmacMD5) }
func TestAXFR_POWERDNS_SHA1(t *testing.T)   { testAXFR(t, "powerdns", HmacSHA1) }
func TestAXFR_POWERDNS_SHA256(t *testing.T) { testAXFR(t, "powerdns", HmacSHA256) }

func TestAXFR_YADIFA_NONE(t *testing.T)   { testAXFR(t, "yadifa", "") }
func TestAXFR_YADIFA_MD5(t *testing.T)    { testAXFR(t, "yadifa", HmacMD5) }
func TestAXFR_YADIFA_SHA1(t *testing.T)   { testAXFR(t, "yadifa", HmacSHA1) }
func TestAXFR_YADIFA_SHA256(t *testing.T) { testAXFR(t, "yadifa", HmacSHA256) }

func testAXFR(t *testing.T, host, alg string) {
	x := new(Transfer)
	x.TsigSecret = map[string]string{
		"wb_md5.":          "Wu/utSasZUkoeCNku152Zw==",
		"wb_sha1_longkey.": "uhMpEhPq/RAD9Bt4mqhfmi+7ZdKmjLQb/lcrqYPXR4s/nnbsqw==",
		"wb_sha256.":       "npfrIJjt/MJOjGJoBNZtsjftKMhkSpIYMv2RzRZt1f8=",
	}
	keyname := map[string]string{
		HmacMD5:    "wb_md5.",
		HmacSHA1:   "wb_sha1_longkey.",
		HmacSHA256: "wb_sha256.",
	}[alg]

	m := new(Msg)
	m.SetAxfr("types.wb.sidnlabs.nl.")
	if keyname != "" {
		m.SetTsig(keyname, alg, 300, time.Now().Unix())
	}
	c, err := x.In(m, host+".sidnlabs.nl:53")
	if err != nil {
		t.Fatal(err)
	}
	for e := range c {
		if e.Error != nil {
			t.Fatal(e.Error)
		}
	}
}
