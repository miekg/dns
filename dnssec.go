package dns

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
)

const (
	// RFC1982 serial arithmetic
	year68 = 2 << (32 - 1)
)

// An RRset is just a bunch a RRs. No restrictions
type RRset []RR

func (r RRset) Len() int           { return len(r) }
func (r RRset) Less(i, j int) bool { return r[i].Header().Name < r[j].Header().Name }
func (r RRset) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }

// Convert an DNSKEY record to a DS record.
func (k *RR_DNSKEY) ToDS(hash int) *RR_DS {
	ds := new(RR_DS)
	ds.Hdr.Name = k.Hdr.Name
	ds.Hdr.Class = k.Hdr.Class
	ds.Hdr.Ttl = k.Hdr.Ttl
	ds.Hdr.Rrtype = TypeDS
	ds.KeyTag = k.KeyTag()
	ds.Algorithm = k.Algorithm
	ds.DigestType = uint8(hash)

	// Generic function that gives back a buffer with the rdata?? TODO(MG)
	// Find the rdata portion for the key (again)
	// (keytag does this too)
	buf := make([]byte, 4096)
	off1, ok := packRR(k, buf, 0)
	if !ok {
		return nil
	}

	start := off1 - int(k.Header().Rdlength)
	end := start + int(k.Header().Rdlength)
	// buf[start:end] is the rdata of the key
	buf = buf[start:end]
	owner := make([]byte, 255)
	off1, ok = packDomainName(k.Hdr.Name, owner, 0)
	if !ok {
		return nil
	}
	/* 
	 * from RFC4034
	 * digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
	 * "|" denotes concatenation
	 * DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.
	 */
	owner = owner[:off1]
	// digest buffer
	digest := append(owner, buf...)

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
func (k *RR_DNSKEY) KeyTag() uint16 {
	var keytag int
	switch k.Algorithm {
	case AlgRSAMD5:
		println("Keytag RSAMD5. Todo")
		keytag = 0
	default:
		// Might encode header length too, so that
		// we dont need to pack/unpack all the time
		// Or a shadow structure, with the wiredata and header
		wire, ok := wireRdata(k)
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
func (s *RR_RRSIG) Verify(rrset RRset, k *RR_DNSKEY) bool {
	// Frist the easy checks
	if s.KeyTag != k.KeyTag() {
		println(s.KeyTag)
		println(k.KeyTag())
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
	signeddata := make([]byte, 10240) // 10 Kb??
	// Copy the sig, except the rrsig data
	// Can this be done easier? TODO(mg)
	s1 := &RR_RRSIG{s.Hdr, s.TypeCovered, s.Algorithm, s.Labels, s.OrigTtl, s.Expiration, s.Inception, s.KeyTag, s.SignerName, ""}
	buf, ok := wireRdata(s1)
	if !ok {
		return false
	}
	copy(signeddata, buf)
	off := len(buf)
	fmt.Fprintf(os.Stderr, "off %d\n", off)

	for _, r := range rrset {
		h := r.Header()
		// RFC 4034: 6.2.  Canonical RR Form. (2) - domain name to lowercase
                name := h.Name
		h.Name = strings.ToLower(h.Name)
		// 6.2.  Canonical RR Form. (3) - domain rdata to lowercaser
		switch h.Rrtype {
		case TypeNS, TypeCNAME, TypeSOA, TypeMB, TypeMG, TypeMR, TypePTR:
		case TypeHINFO, TypeMINFO, TypeMX /* TypeRP, TypeAFSDB, TypeRT */ :
		case TypeSIG /* TypePX, TypeNXT /* TypeNAPTR, TypeKX */ :
		case TypeSRV, /* TypeDNAME, TypeA6 */ TypeRRSIG, TypeNSEC:
			/* do something */
			// lower case the strings rdata //

		}
		// 6.2. Canonical RR Form. (4) - wildcards, don't understand
		// 6.2. Canonical RR Form. (5) - origTTL
                ttl := h.Ttl
		h.Ttl = s.OrigTtl
		off, ok = packRR(r, signeddata, off)
                h.Ttl = ttl // restore the order in the universe
                h.Name = name
		if !ok {
			println("Failure to pack")
			return false
		}
	}
	signeddata = signeddata[:off]
	keybuf := make([]byte, 1024)
	keybuflen := base64.StdEncoding.DecodedLen(len(k.PubKey))
	base64.StdEncoding.Decode(keybuf[0:keybuflen], []byte(k.PubKey))
	sigbuf := make([]byte, 1024)
	sigbuflen := base64.StdEncoding.DecodedLen(len(s.Signature))
	base64.StdEncoding.Decode(sigbuf[0:sigbuflen], []byte(s.Signature))

	switch s.Algorithm {
	case AlgRSASHA1:

	case AlgRSASHA256:
                // RFC 3110, section 2. RSA Public KEY Resource Records
                // Assume length is in the first byte!
                _E := int(keybuf[3]) <<16
                _E += int(keybuf[2]) <<8
                _E += int(keybuf[1])
                pubkey := new(rsa.PublicKey)
                pubkey.E = _E
                pubkey.N = big.NewInt(0)
                pubkey.N.SetBytes(keybuf[4:])
                fmt.Fprintf(os.Stderr, "%s\n", pubkey.N)
        }

	return true
}

// Using RFC1982 calculate if a signature period is valid
func (s *RR_RRSIG) PeriodOK() bool {
	utc := time.UTC().Seconds()
	modi := (int64(s.Inception) - utc) / year68
	mode := (int64(s.Expiration) - utc) / year68
	ti := int64(s.Inception) + (modi * year68)
	te := int64(s.Expiration) + (mode * year68)
	return ti <= utc && utc <= te
}

// Translate the RRSIG's incep. and expir. time to the correct date.
// Taking into account serial arithmetic (RFC 1982)
func timeToDate(t uint32) string {
	utc := time.UTC().Seconds()
	mod := (int64(t) - utc) / year68

	// If needed assume wrap around(s)
	ti := time.SecondsToUTC(int64(t) + (mod * year68)) // abs()? TODO
	return ti.Format("20060102030405")
}
