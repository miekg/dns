package dns

import (
	"testing"
)


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
