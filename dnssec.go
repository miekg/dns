package dns

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/rsa"
	"crypto/rand"
	"encoding/hex"
	"hash"
	"time"
	"io"
	"big"
	"sort"
	"strings"
	"os"
)

// DNSSEC encryption algorithm codes.
const (
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

// The RRSIG needs to be converted to wireformat with some of
// the rdata (the signature) missing. Use this struct to easy
// the conversion (and re-use the pack/unpack functions.
type rrsigWireFmt struct {
	TypeCovered uint16
	Algorithm   uint8
	Labels      uint8
	OrigTtl     uint32
	Expiration  uint32
	Inception   uint32
	KeyTag      uint16
	SignerName  string "domain-name"
	/* No Signature */
}

// Used for converting DNSKEY's rdata to wirefmt.
type dnskeyWireFmt struct {
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey    string "base64"
	/* Nothing is left out */
}

// Calculate the keytag of the DNSKEY.
func (k *RR_DNSKEY) KeyTag() uint16 {
	var keytag int
	switch k.Algorithm {
	case AlgRSAMD5:
		println("Keytag RSAMD5. Todo")
		keytag = 0
	default:
		keywire := new(dnskeyWireFmt)
		keywire.Flags = k.Flags
		keywire.Protocol = k.Protocol
		keywire.Algorithm = k.Algorithm
		keywire.PublicKey = k.PublicKey
		wire := make([]byte, 2048) // TODO(mg) lenght!
		n, ok := packStruct(keywire, wire, 0)
		if !ok {
			return 0
		}
		wire = wire[:n]
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

// Convert an DNSKEY record to a DS record.
func (k *RR_DNSKEY) ToDS(h int) *RR_DS {
	ds := new(RR_DS)
	ds.Hdr.Name = k.Hdr.Name
	ds.Hdr.Class = k.Hdr.Class
	ds.Hdr.Ttl = k.Hdr.Ttl
	ds.Algorithm = k.Algorithm
	ds.DigestType = uint8(h)
	ds.KeyTag = k.KeyTag()

	keywire := new(dnskeyWireFmt)
	keywire.Flags = k.Flags
	keywire.Protocol = k.Protocol
	keywire.Algorithm = k.Algorithm
	keywire.PublicKey = k.PublicKey
	wire := make([]byte, 2048) // TODO(mg) lenght!
	n, ok := packStruct(keywire, wire, 0)
	if !ok {
		return nil
	}
	wire = wire[:n]

	owner := make([]byte, 255)
	off, ok1 := packDomainName(k.Hdr.Name, owner, 0)
	if !ok1 {
		return nil
	}
	owner = owner[:off]
	/* 
	 * from RFC4034
	 * digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
	 * "|" denotes concatenation
	 * DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.
	 */
	// digest buffer
	digest := append(owner, wire...) // another copy TODO(mg)

	switch h {
	case HashSHA1:
		s := sha1.New()
		io.WriteString(s, string(digest))
		ds.Digest = hex.EncodeToString(s.Sum())
	case HashSHA256:
		s := sha256.New()
		io.WriteString(s, string(digest))
		ds.Digest = hex.EncodeToString(s.Sum())
	case HashGOST94:
		/* I have no clue */
	default:
		return nil
	}
	return ds
}

// Sign an RRSet. The Signature needs to be filled in with
// the values: Inception, Expiration, KeyTag, SignerName and Algorithm.
// The rest is copied from the RRset. Returns true when the signing went OK.
// The Signature data in the RRSIG is filled by this method.
// There is no check if rrset is a proper (RFC 2181) RRSet.
func (s *RR_RRSIG) Sign(k PrivateKey, rrset RRset) bool {
	if k == nil {
		return false
	}
	// s.Inception and s.Expiration may be 0 (rollover etc.)
        // the rest must be set
	if s.KeyTag == 0 || len(s.SignerName) == 0 || s.Algorithm == 0 {
	}
	s.Hdr.Rrtype = TypeRRSIG
	s.Hdr.Name = rrset[0].Header().Name
	s.Hdr.Class = rrset[0].Header().Class
	s.OrigTtl = rrset[0].Header().Ttl
	s.TypeCovered = rrset[0].Header().Rrtype
	s.Labels = LabelCount(rrset[0].Header().Name)
	s.TypeCovered = rrset[0].Header().Rrtype

	sigwire := new(rrsigWireFmt)
	sigwire.TypeCovered = s.TypeCovered
	sigwire.Algorithm = s.Algorithm
	sigwire.Labels = s.Labels
	sigwire.OrigTtl = s.OrigTtl
	sigwire.Expiration = s.Expiration
	sigwire.Inception = s.Inception
	sigwire.KeyTag = s.KeyTag
	sigwire.SignerName = s.SignerName

	// Create the desired binary blob
	signdata := make([]byte, DefaultMsgSize)
	n, ok := packStruct(sigwire, signdata, 0)
	if !ok {
		return false
	}
	signdata = signdata[:n]

	// identical to Verify // TODO(mg) seperate function
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
			// lower case the domain rdata //

		}
		// 6.2. Canonical RR Form. (4) - wildcards, don't understand
		// 6.2. Canonical RR Form. (5) - origTTL

		ttl := h.Ttl
		h.Ttl = s.OrigTtl
		wire := make([]byte, DefaultMsgSize)
		off, ok1 := packRR(r, wire, 0)
		if !ok1 {
			println("Failure to pack")
			return false
		}
		wire = wire[:off]
		h.Ttl = ttl // restore the order in the universe
		h.Name = name
		if !ok1 {
			println("Failure to pack")
			return false
		}
		signdata = append(signdata, wire...)
	}

	var signature []byte
	var err os.Error
	switch s.Algorithm {
	case AlgRSASHA1, AlgRSASHA256, AlgRSASHA512, AlgRSAMD5:
		//pubkey := k.pubKeyRSA() // Get the key, need privkey representation
		// Setup the hash as defined for this alg.
		var h hash.Hash
		var ch rsa.PKCS1v15Hash
		switch s.Algorithm {
		case AlgRSAMD5:
			h = md5.New()
			ch = rsa.HashMD5
		case AlgRSASHA1:
			h = sha1.New()
			ch = rsa.HashSHA1
		case AlgRSASHA256:
			h = sha256.New()
			ch = rsa.HashSHA256
		case AlgRSASHA512:
			h = sha512.New()
			ch = rsa.HashSHA512
		default:
			// Illegal Alg
			return false
		}
		// Need privakey representation in godns TODO(mg) see keygen.go
		io.WriteString(h, string(signdata))
		sighash := h.Sum()

		// Get the key from the interface
		switch p := k.(type) {
		case *rsa.PrivateKey:
			signature, err = rsa.SignPKCS1v15(rand.Reader, p, ch, sighash)
			if err != nil {
				return false
			}
			s.Signature = unpackBase64(signature)
		default:
			// Not given the correct key
			return false
		}
	case AlgDH:
	case AlgDSA:
	case AlgECC:
	case AlgECCGOST:
	}

	return true
}

// Validate an RRSet with the signature and key. This is only the
// cryptographic test, the signature validity period most be checked separately.
func (s *RR_RRSIG) Verify(k *RR_DNSKEY, rrset RRset) bool {
	// Frist the easy checks
	if s.KeyTag != k.KeyTag() {
		return false
	}
	if s.Hdr.Class != k.Hdr.Class {
		return false
	}
	if s.Algorithm != k.Algorithm {
		return false
	}
	if s.SignerName != k.Hdr.Name {
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
	sigwire := new(rrsigWireFmt)
	sigwire.TypeCovered = s.TypeCovered
	sigwire.Algorithm = s.Algorithm
	sigwire.Labels = s.Labels
	sigwire.OrigTtl = s.OrigTtl
	sigwire.Expiration = s.Expiration
	sigwire.Inception = s.Inception
	sigwire.KeyTag = s.KeyTag
	sigwire.SignerName = s.SignerName
	// Create the desired binary blob
	signeddata := make([]byte, DefaultMsgSize)
	n, ok := packStruct(sigwire, signeddata, 0)
	if !ok {
		return false
	}
	signeddata = signeddata[:n]

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
			// lower case the domain rdata //

		}
		// 6.2. Canonical RR Form. (4) - wildcards, don't understand
		// 6.2. Canonical RR Form. (5) - origTTL

		ttl := h.Ttl
		h.Ttl = s.OrigTtl
		wire := make([]byte, DefaultMsgSize)
		off, ok1 := packRR(r, wire, 0)
		if !ok1 {
			println("Failure to pack")
			return false
		}
		wire = wire[:off]
		h.Ttl = ttl // restore the order in the universe
		h.Name = name
		if !ok1 {
			println("Failure to pack")
			return false
		}
		signeddata = append(signeddata, wire...)
	}

	sigbuf := s.sigBuf() // Get the binary signature data

	var err os.Error
	switch s.Algorithm {
	case AlgRSASHA1, AlgRSASHA256, AlgRSASHA512, AlgRSAMD5:
		pubkey := k.pubKeyRSA() // Get the key
		// Setup the hash as defined for this alg.
		var h hash.Hash
		var ch rsa.PKCS1v15Hash
		switch s.Algorithm {
		case AlgRSAMD5:
			h = md5.New()
			ch = rsa.HashMD5
		case AlgRSASHA1:
			h = sha1.New()
			ch = rsa.HashSHA1
		case AlgRSASHA256:
			h = sha256.New()
			ch = rsa.HashSHA256
		case AlgRSASHA512:
			h = sha512.New()
			ch = rsa.HashSHA512
		}
		io.WriteString(h, string(signeddata))
		sighash := h.Sum()
		err = rsa.VerifyPKCS1v15(pubkey, ch, sighash, sigbuf)
	case AlgDH:
	case AlgDSA:
	case AlgECC:
	case AlgECCGOST:
	default:
		// Unknown Alg
		return false
	}
	return err == nil
}

// Use RFC1982 to calculate if a signature period is valid.
func (s *RR_RRSIG) PeriodOK() bool {
	utc := time.UTC().Seconds()
	modi := (int64(s.Inception) - utc) / Year68
	mode := (int64(s.Expiration) - utc) / Year68
	ti := int64(s.Inception) + (modi * Year68)
	te := int64(s.Expiration) + (mode * Year68)
	return ti <= utc && utc <= te
}

// Return the signatures base64 encodedig sigdata as a byte slice.
func (s *RR_RRSIG) sigBuf() []byte {
	sigbuf, err := packBase64([]byte(s.Signature))
	if err != nil {
		return nil
	}
	return sigbuf
}

// Extract the RSA public key from the Key record
func (k *RR_DNSKEY) pubKeyRSA() *rsa.PublicKey {
	keybuf, err := packBase64([]byte(k.PublicKey))
	if err != nil {
		return nil
	}

	// RFC 2537/3110, section 2. RSA Public KEY Resource Records
	// Length is in the 0th byte, unless its zero, then it
	// it in bytes 1 and 2 and its a 16 bit number
	explen := uint16(keybuf[0])
	keyoff := 1
	if explen == 0 {
		explen = uint16(keybuf[1])<<8 | uint16(keybuf[2])
		keyoff = 3
	}
	pubkey := new(rsa.PublicKey)
	pubkey.N = big.NewInt(0)
	shift := (explen - 1) * 8
	for i := int(explen - 1); i >= 0; i-- {
		pubkey.E += int(keybuf[keyoff+i]) << shift
		shift -= 8
	}
	pubkey.N.SetBytes(keybuf[keyoff+int(explen):])
	return pubkey
}

// Set the public key (the value E and N)
func (k *RR_DNSKEY) setPublicKeyRSA(_E int, _N *big.Int) {
	buf := exponentToBuf(_E)
	buf = append(buf, _N.Bytes()...)
	k.PublicKey = unpackBase64(buf)
	return
}

// Set the public key (the value E and N)
// RFC 3110: Section 2. RSA Public KEY Resource Records
func exponentToBuf(_E int) []byte {
	var buf []byte
	i := big.NewInt(int64(_E))
	if len(i.Bytes()) < 256 {
		buf = make([]byte, 1)
		buf[0] = uint8(len(i.Bytes()))
	} else {
		buf = make([]byte, 3)
		buf[0] = 0
		buf[1] = uint8(len(i.Bytes()) >> 8)
		buf[2] = uint8(len(i.Bytes()))
	}
	buf = append(buf, i.Bytes()...)
	return buf
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
