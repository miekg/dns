// Package dnssec implements all client side DNSSEC function, like
// validation, keytag/DS calculation. 
package dnssec

// Put tsig and tkey stuff here too

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/rsa"
	"encoding/hex"
	"encoding/base64"
	"time"
	"io"
        "big"
	"sort"
	"strings"
	"fmt" //tmp
	"os"  //tmp
        "dns"
)

// DNSSEC encryption algorithm codes.
const (
        // DNSSEC algorithms
        AlgRSAMD5    = 1
        AlgDH        = 2
        AlgDSA       = 3
        AlgECC       = 4
        AlgRSASHA1   = 5
        AlgRSASHA256 = 8
        AlgRSASHA512 = 10
        AlgECCGOST   = 12
)

// DNSSEC hashing codes.
const (
        HashSHA1 = iota
        HashSHA256
        HashGOST94
)

// Convert an DNSKEY record to a DS record.
func ToDS(k *dns.RR_DNSKEY, hash int) *dns.RR_DS {
	ds := new(dns.RR_DS)
	ds.Hdr.Name = k.Hdr.Name
	ds.Hdr.Class = k.Hdr.Class
	ds.Hdr.Ttl = k.Hdr.Ttl
	ds.Algorithm = k.Algorithm
	ds.DigestType = uint8(hash)
	ds.KeyTag = KeyTag(k)

	wire, ok := dns.WireRdata(k)
	if !ok {
		return nil
	}

	owner,ok1 := dns.WireDomainName(k.Hdr.Name)
	if !ok1 {
		return nil
	}
	/* 
	 * from RFC4034
	 * digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
	 * "|" denotes concatenation
	 * DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.
	 */
	// digest buffer
	digest := append(owner, wire...)  // another copy TODO(mg)

	switch hash {
	case HashSHA1:
		s := sha1.New()
		io.WriteString(s, string(digest))
		ds.Digest = hex.EncodeToString(s.Sum())
	case HashSHA256:
		s := sha256.New()
		io.WriteString(s, string(digest))
		ds.Digest = hex.EncodeToString(s.Sum())
	case HashGOST94:

	default:
		// wrong hash value
		return nil
	}
	return ds
}

// Calculate the keytag of the DNSKEY.
func KeyTag(k *dns.RR_DNSKEY) uint16 {
	var keytag int
	switch k.Algorithm {
	case AlgRSAMD5:
		println("Keytag RSAMD5. Todo")
		keytag = 0
	default:
		// Might encode header length too, so that
		// we dont need to pack/unpack all the time
		// Or a shadow structure, with the wiredata and header
		wire, ok := dns.WireRdata(k)
		if !ok {
			return 0
		}
		for i, v := range wire {
			if i&1 != 0 {
				keytag += int(v) // must be larger than uint32
			} else {
				keytag += int(v) << 8
			}
		}
		keytag += (keytag >> 16) & 0xFFFF
		keytag &= 0xFFFF
	}
	return uint16(keytag)
}

// Validate an rrset with the signature and key. This is the
// cryptographic test, the validity period most be check separately.
func Verify(s *dns.RR_RRSIG, k *dns.RR_DNSKEY, rrset dns.RRset) bool {
	// Frist the easy checks
	if s.KeyTag != KeyTag(k) {
		println(s.KeyTag)
		println(KeyTag(k))
		return false
	}
	if s.Hdr.Class != k.Hdr.Class {
		println("Class")
		return false
	}
	if s.Algorithm != k.Algorithm {
		println("Class")
		return false
	}
	if s.SignerName != k.Hdr.Name {
		println(s.SignerName)
		println(k.Hdr.Name)
		return false
	}
	for _, r := range rrset {
		if r.Header().Class != s.Hdr.Class {
			return false
		}
		if r.Header().Rrtype != s.TypeCovered {
			return false
		}
		// Number of labels. TODO(mg) add helper functions
	}
	sort.Sort(rrset)

	// RFC 4035 5.3.2.  Reconstructing the Signed Data
	// Copy the sig, except the rrsig data
	s1 := &dns.RR_RRSIG{s.Hdr, s.TypeCovered, s.Algorithm, s.Labels, s.OrigTtl, s.Expiration, s.Inception, s.KeyTag, s.SignerName, ""}
	signeddata, ok := dns.WireRdata(s1)
	if !ok {
		return false
	}
        println("length of date s1", s1.Hdr.Rdlength)
        println("length of signeddata buf", len(signeddata))

fmt.Printf("PRE SIGNEDDATA BUF %v\n", signeddata)

	for _, r := range rrset {
		h := r.Header()
		// RFC 4034: 6.2.  Canonical RR Form. (2) - domain name to lowercase
                name := h.Name
		h.Name = strings.ToLower(h.Name)
		// 6.2.  Canonical RR Form. (3) - domain rdata to lowercaser
		switch h.Rrtype {
		case dns.TypeNS, dns.TypeCNAME, dns.TypeSOA, dns.TypeMB, dns.TypeMG, dns.TypeMR, dns.TypePTR:
		case dns.TypeHINFO, dns.TypeMINFO, dns.TypeMX /* dns.TypeRP, dns.TypeAFSDB, dns.TypeRT */ :
		case dns.TypeSIG /* dns.TypePX, dns.TypeNXT /* dns.TypeNAPTR, dns.TypeKX */ :
		case dns.TypeSRV, /* dns.TypeDNAME, dns.TypeA6 */ dns.TypeRRSIG, dns.TypeNSEC:
			/* do something */
			// lower case the strings rdata //

		}
		// 6.2. Canonical RR Form. (4) - wildcards, don't understand
		// 6.2. Canonical RR Form. (5) - origTTL
                ttl := h.Ttl
		h.Ttl = s.OrigTtl
                wire, ok1 := dns.WireRR(r)
                h.Ttl = ttl // restore the order in the universe
                h.Name = name
		if !ok1 {
			println("Failure to pack")
			return false
		}
                signeddata = append(signeddata, wire...)
                fmt.Printf("WIREBUF %v\n", wire)
                fmt.Printf("SIGNEDDATA BUF %v\n", signeddata)
	}
        fmt.Fprintf(os.Stderr, "lengthed signeddata %d\n", len(signeddata))
	keybuf := make([]byte, 1024)
	keybuflen := base64.StdEncoding.DecodedLen(len(k.PubKey))
	base64.StdEncoding.Decode(keybuf[0:keybuflen], []byte(k.PubKey))
        keybuf = keybuf[:keybuflen]

        fmt.Printf("\n%d KEYBUF %v\n", keybuflen, keybuf)

	sigbuf := make([]byte, 1024)
	sigbuflen := base64.StdEncoding.DecodedLen(len(s.Signature))
	base64.StdEncoding.Decode(sigbuf[0:sigbuflen], []byte(s.Signature))
        sigbuf = sigbuf[:sigbuflen-1]                                           // Why the -1 here, and not for the keybuf??
        fmt.Fprintf(os.Stderr, "len of sigbuf: %d\n", len(sigbuf))

        fmt.Printf("\nSIGBUF %v\n", sigbuf)

	switch s.Algorithm {
	case AlgRSASHA1:

	case AlgRSASHA256:
                // RFC 3110, section 2. RSA Public KEY Resource Records
                // Assume length is in the first byte!
                // keybuf[1]
                _E := int(keybuf[3]) <<16
                _E += int(keybuf[2]) <<8
                _E += int(keybuf[1])
                println("_E", _E)
                pubkey := new(rsa.PublicKey)
                pubkey.E = _E
                pubkey.N = big.NewInt(0)
                pubkey.N.SetBytes(keybuf[4:])
                fmt.Fprintf(os.Stderr, "keybug len %d", len(keybuf[4:]))
                fmt.Fprintf(os.Stderr, "PubKey %s\n", pubkey.N)

        // Hash the signeddata
        s := sha256.New()
        io.WriteString(s, string(signeddata))
        sighash := s.Sum()
        println("sig hash", len(sighash))

                err := rsa.VerifyPKCS1v15(pubkey, rsa.HashSHA256, sighash, sigbuf)
                if err == nil {
                        fmt.Fprintf(os.Stderr, "NO SHIT Sherlock!!\n")
                } else {
                        fmt.Fprintf(os.Stderr, "*********** %v\n", err)
                }
        }

	return true
}

// Using RFC1982 calculate if a signature period is valid
func PeriodOK(s *dns.RR_RRSIG) bool {
	utc := time.UTC().Seconds()
	modi := (int64(s.Inception) - utc) / dns.Year68
	mode := (int64(s.Expiration) - utc) / dns.Year68
	ti := int64(s.Inception) + (modi * dns.Year68)
	te := int64(s.Expiration) + (mode * dns.Year68)
	return ti <= utc && utc <= te
}

// Map for algorithm names. 
var alg_str = map[uint8]string{
        AlgRSAMD5:    "RSAMD5",
        AlgDH:        "DH",
        AlgDSA:       "DSA",
        AlgRSASHA1:   "RSASHA1",
        AlgRSASHA256: "RSASHA256",
        AlgRSASHA512: "RSASHA512",
        AlgECCGOST:   "ECC-GOST",
}
