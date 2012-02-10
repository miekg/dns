// Copyright 2012 Miek Gieben. All rights reserved.

// DNSSEC
//
// DNSSEC (DNS Security Extension) adds a layer of security to the DNS. It
// uses public key cryptography to securely sign resource records. The
// public keys are stored in DNSKEY records and the signatures in RRSIG records.
package dns

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"io"
	"math/big"
	"sort"
	"strings"
	"time"
)

// DNSSEC encryption algorithm codes.
const (
	RSAMD5           = 1
	DH               = 2
	DSA              = 3
	ECC              = 4
	RSASHA1          = 5
	DSANSEC3SHA1     = 6
	RSASHA1NSEC3SHA1 = 7
	RSASHA256        = 8
	RSASHA512        = 10
	ECCGOST          = 12
	ECDSAP256SHA256  = 13
	ECDSAP384SHA384  = 14
	PRIVATEDNS       = 253 // Private (experimental keys)
	PRIVATEOID       = 254
)

// DNSSEC hashing algorithm codes.
const (
	_      = iota
	SHA1   // RFC 4034
	SHA256 // RFC 4509 
	GOST94 // RFC 5933
	SHA384 // Experimental
)

// DNSKEY flag values.
const (
	SEP    = 1
	ZONE   = 1 << 7
	REVOKE = 1 << 8
)

// The RRSIG needs to be converted to wireformat with some of
// the rdata (the signature) missing. Use this struct to easy
// the conversion (and re-use the pack/unpack functions).
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
	PublicKey string "base64"
	/* Nothing is left out */
}

// KeyTag calculates the keytag (or key-id) of the DNSKEY.
func (k *RR_DNSKEY) KeyTag() uint16 {
	if k == nil {
		return 0
	}
	var keytag int
	switch k.Algorithm {
	case RSAMD5:
		keytag = 0
	default:
		keywire := new(dnskeyWireFmt)
		keywire.Flags = k.Flags
		keywire.Protocol = k.Protocol
		keywire.Algorithm = k.Algorithm
		keywire.PublicKey = k.PublicKey
		wire := make([]byte, DefaultMsgSize)
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

// ToDS converts a DNSKEY record to a DS record.
func (k *RR_DNSKEY) ToDS(h int) *RR_DS {
	if k == nil {
		return nil
	}
	ds := new(RR_DS)
	ds.Hdr.Name = k.Hdr.Name
	ds.Hdr.Class = k.Hdr.Class
	ds.Hdr.Rrtype = TypeDS
	ds.Hdr.Ttl = k.Hdr.Ttl
	ds.Algorithm = k.Algorithm
	ds.DigestType = uint8(h)
	ds.KeyTag = k.KeyTag()

	keywire := new(dnskeyWireFmt)
	keywire.Flags = k.Flags
	keywire.Protocol = k.Protocol
	keywire.Algorithm = k.Algorithm
	keywire.PublicKey = k.PublicKey
	wire := make([]byte, DefaultMsgSize)
	n, ok := packStruct(keywire, wire, 0)
	if !ok {
		return nil
	}
	wire = wire[:n]

	owner := make([]byte, 255)
	off, ok1 := PackDomainName(k.Hdr.Name, owner, 0, nil, false)
	if !ok1 {
		return nil
	}
	owner = owner[:off]
	// RFC4034:
	// digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
	// "|" denotes concatenation
	// DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.

	// digest buffer
	digest := append(owner, wire...) // another copy

	switch h {
	case SHA1:
		s := sha1.New()
		io.WriteString(s, string(digest))
		ds.Digest = hex.EncodeToString(s.Sum(nil))
	case SHA256:
		s := sha256.New()
		io.WriteString(s, string(digest))
		ds.Digest = hex.EncodeToString(s.Sum(nil))
	case SHA384:
		s := sha512.New384()
		io.WriteString(s, string(digest))
		ds.Digest = hex.EncodeToString(s.Sum(nil))
	case GOST94:
		/* I have no clue */
	default:
		return nil
	}
	return ds
}

// Sign signs an RRSet. The signature needs to be filled in with
// the values: Inception, Expiration, KeyTag, SignerName and Algorithm.
// The rest is copied from the RRset. Sign returns true when the signing went OK,
// otherwise false.
// The signature data in the RRSIG is filled by this method.
// There is no check if RRSet is a proper (RFC 2181) RRSet.
func (s *RR_RRSIG) Sign(k PrivateKey, rrset []RR) error {
	if k == nil {
		return ErrPrivKey
	}
	// s.Inception and s.Expiration may be 0 (rollover etc.), the rest must be set
	if s.KeyTag == 0 || len(s.SignerName) == 0 || s.Algorithm == 0 {
		return ErrKey
	}

	s.Hdr.Rrtype = TypeRRSIG
	s.Hdr.Name = rrset[0].Header().Name
	s.Hdr.Class = rrset[0].Header().Class
	s.OrigTtl = rrset[0].Header().Ttl
	s.TypeCovered = rrset[0].Header().Rrtype
	s.TypeCovered = rrset[0].Header().Rrtype
	s.Labels, _, _ = IsDomainName(rrset[0].Header().Name)
	// ...
	if strings.HasPrefix(rrset[0].Header().Name, "*") {
		s.Labels-- // wildcard, remove from label count
	}

	sigwire := new(rrsigWireFmt)
	sigwire.TypeCovered = s.TypeCovered
	sigwire.Algorithm = s.Algorithm
	sigwire.Labels = s.Labels
	sigwire.OrigTtl = s.OrigTtl
	sigwire.Expiration = s.Expiration
	sigwire.Inception = s.Inception
	sigwire.KeyTag = s.KeyTag
	sigwire.SignerName = strings.ToLower(s.SignerName)

	// Create the desired binary blob
	signdata := make([]byte, DefaultMsgSize)
	n, ok := packStruct(sigwire, signdata, 0)
	if !ok {
		return ErrPack
	}
	signdata = signdata[:n]
	wire := rawSignatureData(rrset, s)
	if wire == nil {
		return ErrSigGen
	}
	signdata = append(signdata, wire...)

	var sighash []byte
	var h hash.Hash
	var ch crypto.Hash // Only need for RSA
	switch s.Algorithm {
	case RSAMD5:
		h = md5.New()
		ch = crypto.MD5
	case RSASHA1, RSASHA1NSEC3SHA1:
		h = sha1.New()
		ch = crypto.SHA1
	case RSASHA256, ECDSAP256SHA256:
		h = sha256.New()
		ch = crypto.SHA256
	case ECDSAP384SHA384:
		h = sha512.New384()
	case RSASHA512:
		h = sha512.New()
		ch = crypto.SHA512
	default:
		return ErrAlg
	}
	io.WriteString(h, string(signdata))
	sighash = h.Sum(nil)

	switch p := k.(type) {
	case *rsa.PrivateKey:
		signature, err := rsa.SignPKCS1v15(rand.Reader, p, ch, sighash)
		if err != nil {
			return err
		}
		s.Signature = unpackBase64(signature)
	case *ecdsa.PrivateKey:
		r1, s1, err := ecdsa.Sign(rand.Reader, p, sighash)
		if err != nil {
			return err
		}
		signature := r1.Bytes()
		signature = append(signature, s1.Bytes()...)
		s.Signature = unpackBase64(signature)
	default:
		// Not given the correct key
		return ErrKeyAlg
	}
	return nil
}

// Verify validates an RRSet with the signature and key. This is only the
// cryptographic test, the signature validity period must be checked separately.
// This function (temporary) modifies the RR for the validation to work. 
func (s *RR_RRSIG) Verify(k *RR_DNSKEY, rrset []RR) error {
	// First the easy checks
	if s.KeyTag != k.KeyTag() {
		return ErrKey
	}
	if s.Hdr.Class != k.Hdr.Class {
		return ErrKey
	}
	if s.Algorithm != k.Algorithm {
		return ErrKey
	}
	if s.SignerName != k.Hdr.Name {
		return ErrKey
	}
	for _, r := range rrset {
		if r.Header().Class != s.Hdr.Class {
			return ErrRRset
		}
		if r.Header().Rrtype != s.TypeCovered {
			return ErrRRset
		}
	}

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
	sigwire.SignerName = strings.ToLower(s.SignerName)
	// Create the desired binary blob
	signeddata := make([]byte, DefaultMsgSize)
	n, ok := packStruct(sigwire, signeddata, 0)
	if !ok {
		return ErrPack
	}
	signeddata = signeddata[:n]
	wire := rawSignatureData(rrset, s)
	if wire == nil {
		return ErrSigGen
	}
	signeddata = append(signeddata, wire...)

	sigbuf := s.sigBuf() // Get the binary signature data
	if s.Algorithm == PRIVATEDNS {
		// remove the domain name and assume its our
	}

	switch s.Algorithm {
	case RSASHA1, RSASHA1NSEC3SHA1, RSASHA256, RSASHA512, RSAMD5:
		pubkey := k.pubKeyRSA() // Get the key
		// Setup the hash as defined for this alg.
		var h hash.Hash
		var ch crypto.Hash
		switch s.Algorithm {
		case RSAMD5:
			h = md5.New()
			ch = crypto.MD5
		case RSASHA1, RSASHA1NSEC3SHA1:
			h = sha1.New()
			ch = crypto.SHA1
		case RSASHA256:
			h = sha256.New()
			ch = crypto.SHA256
		case RSASHA512:
			h = sha512.New()
			ch = crypto.SHA512
		}
		io.WriteString(h, string(signeddata))
		sighash := h.Sum(nil)
		return rsa.VerifyPKCS1v15(pubkey, ch, sighash, sigbuf)
	}
	// Unknown alg
	return ErrAlg
}

// ValidityPeriod uses RFC1982 serial arithmetic to calculate 
// if a signature period is valid.
func (s *RR_RRSIG) ValidityPeriod() bool {
	utc := time.Now().UTC().Unix()
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

// Extract the Curve public key from the Key record
func (k *RR_DNSKEY) pubKeyCurve() *ecdsa.PublicKey {
	keybuf, err := packBase64([]byte(k.PublicKey))
	if err != nil {
		return nil
	}
	var c elliptic.Curve
	switch k.Algorithm {
	case ECDSAP256SHA256:
		c = elliptic.P256()
	case ECDSAP384SHA384:
		c = elliptic.P384()
	}
	x, y := elliptic.Unmarshal(c, keybuf)
	pubkey := new(ecdsa.PublicKey)
	pubkey.X = x
	pubkey.Y = y
	pubkey.Curve = c
	return pubkey
}

// Set the public key (the value E and N)
func (k *RR_DNSKEY) setPublicKeyRSA(_E int, _N *big.Int) bool {
	if _E == 0 || _N == nil {
		return false
	}
	buf := exponentToBuf(_E)
	buf = append(buf, _N.Bytes()...)
	k.PublicKey = unpackBase64(buf)
	return true
}

// Set the public key for Elliptic Curves
func (k *RR_DNSKEY) setPublicKeyCurve(_X, _Y *big.Int) bool {
	if _X == nil || _Y == nil {
		return false
	}
	buf := curveToBuf(_X, _Y)
	k.PublicKey = unpackBase64(buf)
	return true
}

// Set the public key (the values E and N) for RSA
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

// Set the public key for X and Y for Curve. Experiment.
func curveToBuf(_X, _Y *big.Int) []byte {
	buf := _X.Bytes()
	buf = append(buf, _Y.Bytes()...)
	return buf
}

type wireSlice [][]byte

func (p wireSlice) Len() int { return len(p) }
func (p wireSlice) Less(i, j int) bool {
	_, ioff, _ := UnpackDomainName(p[i], 0)
	_, joff, _ := UnpackDomainName(p[j], 0)
	return bytes.Compare(p[i][ioff+10:], p[j][joff+10:]) < 0
}
func (p wireSlice) Swap(i, j int) { p[i], p[j] = p[j], p[i] }

// Return the raw signature data. The data in []RR is modified in 
// this function.
func rawSignatureData(rrset []RR, s *RR_RRSIG) (buf []byte) {
	wires := make(wireSlice, len(rrset))
	for i, r := range rrset {
		h := r.Header()
		name := h.Name
		labels := SplitLabels(h.Name)
		// 6.2. Canonical RR Form. (4) - wildcards
		if len(labels) > int(s.Labels) {
			// Wildcard
			h.Name = "*."+strings.Join(labels[len(labels)-int(s.Labels):], ".") + "."
		}
		// RFC 4034: 6.2.  Canonical RR Form. (2) - domain name to lowercase
		h.Name = strings.ToLower(h.Name)
		// 6.2. Canonical RR Form. (3) - domain rdata to lowercase.  -- Deprecated.
		// 6.2. Canonical RR Form. (5) - origTTL
		ttl := h.Ttl
		wire := make([]byte, r.Len()*2)
		h.Ttl = s.OrigTtl
		off, ok1 := packRR(r, wire, 0, nil, false)
		if !ok1 {
			return nil
		}
		h.Ttl = ttl // restore the order in the universe
		wire = wire[:off]
		h.Name = name
		wires[i] = wire
	}
	sort.Sort(wires)
	for _, wire := range wires {
		buf = append(buf, wire...)
	}
	return
}

// Map for algorithm names.
var Alg_str = map[uint8]string{
	RSAMD5:           "RSAMD5",
	DH:               "DH",
	DSA:              "DSA",
	RSASHA1:          "RSASHA1",
	DSANSEC3SHA1:     "DSA-NSEC3-SHA1",
	RSASHA1NSEC3SHA1: "RSASHA1-NSEC3-SHA1",
	RSASHA256:        "RSASHA256",
	RSASHA512:        "RSASHA512",
	ECCGOST:          "ECC-GOST",
	ECDSAP256SHA256:  "ECDSAP256SHA256",
	ECDSAP384SHA384:  "ECDSAP384SHA384",
	PRIVATEDNS:       "PRIVATEDNS",
	PRIVATEOID:       "PRIVATEOID",
}
