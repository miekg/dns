package dns

import (
	"testing"
        "strings"
        "fmt"
        "os"
)

func TestSecure(t *testing.T) {
        soa := new(RR_SOA)
	soa.Hdr = RR_Header{"miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
        soa.Mbox = "miekg.atoom.net."
        soa.Serial = 1293945905
        soa.Refresh = 14400
        soa.Retry = 3600
        soa.Expire = 604800
        soa.Minttl = 86400

	sig := new(RR_RRSIG)
        sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = TypeSOA
	sig.Algorithm = AlgRSASHA256
	sig.Labels = 2
        sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
        sig.Inception = 1293942305 // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.OrigTtl = 14400
	sig.KeyTag = 12051
	sig.SignerName = "miek.nl."
	sig.Signature = "oMCbslaAVIp/8kVtLSms3tDABpcPRUgHLrOR48OOplkYo+8TeEGWwkSwaz/MRo2fB4FxW0qj/hTlIjUGuACSd+b1wKdH5GvzRJc2pFmxtCbm55ygAh4EUL0F6U5cKtGJGSXxxg6UFCQ0doJCmiGFa78LolaUOXImJrk6AFrGa0M="

	key := new(RR_DNSKEY)
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = AlgRSASHA256
	key.PubKey = "AwEAAcNEU67LJI5GEgF9QLNqLO1SMq1EdoQ6E9f85ha0k0ewQGCblyW2836GiVsm6k8Kr5ECIoMJ6fZWf3CQSQ9ycWfTyOHfmI3eQ/1Covhb2y4bAmL/07PhrL7ozWBW3wBfM335Ft9xjtXHPy7ztCbV9qZ4TVDTW/Iyg0PiwgoXVesz"

        fmt.Fprintf(os.Stderr, "%v\n%v\n", sig, soa)
        // It should validate. Period is checked seperately, so this will keep on working
        if ! sig.Verify(key, []RR{soa}) {
                t.Log("Failure to validate")
                t.Fail()
        } else {
                println("It validates!!")
        }
}

func TestSignature(t *testing.T) {
	sig := new(RR_RRSIG)
	sig.Hdr.Name = "miek.nl."
	sig.Hdr.Class = ClassINET
	sig.Hdr.Ttl = 3600
	sig.TypeCovered = TypeDNSKEY
	sig.Algorithm = AlgRSASHA1
	sig.Labels = 2
	sig.OrigTtl = 4000
	sig.Expiration = 1000 //Thu Jan  1 02:06:40 CET 1970
	sig.Inception = 800   //Thu Jan  1 01:13:20 CET 1970
	sig.KeyTag = 34641
	sig.SignerName = "miek.nl."
	sig.Signature = "AwEAAaHIwpx3w4VHKi6i1LHnTaWeHCL154Jug0Rtc9ji5qwPXpBo6A5sRv7cSsPQKPIwxLpyCrbJ4mr2L0EPOdvP6z6YfljK2ZmTbogU9aSU2fiq/4wjxbdkLyoDVgtO+JsxNN4bjr4WcWhsmk1Hg93FV9ZpkWb0Tbad8DFqNDzr//kZ"

	// Should not be valid
	if sig.PeriodOK() {
		t.Log("Should not be valid")
		t.Fail()
	}

	sig.Inception = 315565800   //Tue Jan  1 10:10:00 CET 1980
	sig.Expiration = 4102477800 //Fri Jan  1 10:10:00 CET 2100
	if !sig.PeriodOK() {
		t.Log("Should be valid")
		t.Fail()
	}
}

func TestSignVerify(t *testing.T) {
	// The record we want to sign
	soa := new(RR_SOA)
	soa.Hdr = RR_Header{"miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// With this key
	key := new(RR_DNSKEY)
        key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = AlgRSASHA256
	privkey, _ := key.Generate(512)
        fmt.Fprintf(os.Stderr, "Key tag: %d\n", key.KeyTag())

	// Fill in the values of the Sig, before signing
	sig := new(RR_RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = LabelCount(soa.Hdr.Name)
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = AlgRSASHA256

	// zal wel goed zijn
	if !sig.Sign(privkey, []RR{soa}) {
		t.Log("Failure to sign the SOA record")
		t.Fail()
	}
        fmt.Fprintf(os.Stderr, "%v\n%v\n%v\n", soa, key, sig)
	if !sig.Verify(key, []RR{soa}) {
		t.Log("Failure to validate")
		t.Fail()
	} else {
		println("It validates!!")
	}
}

func TestKeyGen(t *testing.T) {
	key := new(RR_DNSKEY)
	key.Hdr.Name = "miek.nl."
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 3600
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = AlgRSASHA256
        key.Generate(512)
}


/*
func TestDnskey(t *testing.T) {
        return
	// This key was generate with LDNS:
	// ldns-keygen -a RSASHA256 -r /dev/urandom -b 1024 miek.nl 
	// Show that we have al the RSA parameters and can check them
	// here to see what I came up with
	key := new(RR_DNSKEY)
	key.Hdr.Name = "miek.nl."
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 3600
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = AlgRSASHA256
	key.PubKey = "AwEAAcELcuxHosJX3LjbR6EFzsqI3mKivwvO6Y5Kzt/OXYmLQUI8tnOrX9ilT/0qGraxoONayVX3A6bl1pG3h/xOxVEGcJGqbrZnhr2+4S9tW2GWQwevV+NhinE7v6MCCCheVCnAPh0KFb/u14ng3DQizP1spBU/NoAN31l678snBpZX"
	fmt.Printf("%v\n", key)

	soa := new(RR_SOA)
	soa.Hdr = RR_Header{"Miek.nl.", TypeSOA, ClassINET, 875, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293513905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	sig := new(RR_RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = TypeSOA
	sig.Algorithm = AlgRSASHA256
	sig.Labels = 2
	sig.Expiration = 1296098705 // date '+%s' -d"2011-01-27 04:25:05
	sig.Inception = 1293506705
	sig.OrigTtl = 14400
	//sig.KeyTag = 12051
	sig.KeyTag = 12273 //faked
	sig.SignerName = "miek.nl."
	sig.Signature = "kLq/5oFy3Sh5ZxPGFMCyHq8MtN6E17R1Ln9+bJ2Q76YYAxFE8Xlie33A1GFctH2uhzRzJKuP/JSjUkrvGk2rjBm32z9zXtZsKx/4yV0da2nLRm44NOmX6gsP4Yia8mdqPUajjkyLzAzU2bevtesJm0Z65AcmPdq3tUZODdRAcng="

	sig.Verify(key, []RR{soa})

	// From Kmiek.nl*.private
        openssl := "135560614087352210480379313279722604826647214111257577861451621491284835543707521986085999189597017237768514876957888744370440811423088511394629855684615382349190289731989185193184712980579812986523080792122141528583964882610028199770199112837017606561901919812183422914622295620927795008308854924436086101591"
        println("OPENSSL key: what should be is: ",openssl)
}
*/

func TestTag(t *testing.T) {
	key := new(RR_DNSKEY)
	key.Hdr.Name = "miek.nl."
        key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 3600
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = AlgRSASHA256
	key.PubKey = "AwEAAcNEU67LJI5GEgF9QLNqLO1SMq1EdoQ6E9f85ha0k0ewQGCblyW2836GiVsm6k8Kr5ECIoMJ6fZWf3CQSQ9ycWfTyOHfmI3eQ/1Covhb2y4bAmL/07PhrL7ozWBW3wBfM335Ft9xjtXHPy7ztCbV9qZ4TVDTW/Iyg0PiwgoXVesz"

        tag := key.KeyTag()
        if tag != 12051 {
                t.Logf("%v\n", key)
                t.Logf("Wrong key tag: %d\n", tag)
                t.Fail()
        }
}

func TestKeyGenRSA(t *testing.T) {

        return          // Tijdelijk uit TODO(mg)
	key := new(RR_DNSKEY)
	key.Hdr.Name = "miek.nl."
        key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 3600
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = AlgRSASHA256
        length := 2048
        priv, _ := key.Generate(length)

        soa := new(RR_SOA)
        soa.Hdr = RR_Header{"miek.nl.", TypeSOA, ClassINET, 14400, 0}
        soa.Ns = "open.nlnetlabs.nl."
        soa.Mbox = "miekg.atoom.net."
        soa.Serial = 1293945905
        soa.Refresh = 14400
        soa.Retry = 3600
        soa.Expire = 604800
        soa.Minttl = 86400

        sig := new(RR_RRSIG)
        sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
        sig.TypeCovered = TypeSOA
        sig.Algorithm = AlgRSASHA256
        sig.Labels = 2
        sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
        sig.Inception = 1293942305 // date -u '+%s' -d"2011-01-02 04:25:05"
        sig.OrigTtl = 14400
        sig.KeyTag = key.KeyTag()
        sig.SignerName = "miek.nl."

        sig.Sign(priv, []RR{soa})

        s := key.PrivateKeyString(priv)
        fmt.Printf("%s\n", s)

        fmt.Printf("%v\n", sig)
}

func TestKeyToDS(t *testing.T) {
	key := new(RR_DNSKEY)
	key.Hdr.Name = "miek.nl"
        key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 3600
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = AlgRSASHA256
	key.PubKey = "AwEAAcNEU67LJI5GEgF9QLNqLO1SMq1EdoQ6E9f85ha0k0ewQGCblyW2836GiVsm6k8Kr5ECIoMJ6fZWf3CQSQ9ycWfTyOHfmI3eQ/1Covhb2y4bAmL/07PhrL7ozWBW3wBfM335Ft9xjtXHPy7ztCbV9qZ4TVDTW/Iyg0PiwgoXVesz"

        ds := key.ToDS(HashSHA1)
        if strings.ToUpper(ds.Digest) != "B5121BDB5B8D86D0CC5FFAFBAAABE26C3E20BAC1" {
                t.Logf("Wrong DS digest for Sha1\n%v\n", ds)
                t.Fail()
        }
}
