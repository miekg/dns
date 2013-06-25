// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNSSEC
//
// DNSSEC (DNS Security Extension) adds a layer of security to the DNS. It
// uses public key cryptography to sign resource records. The
// public keys are stored in DNSKEY records and the signatures in RRSIG records.
//
// Requesting DNSSEC information for a zone is done by adding the DO (DNSSEC OK) bit
// to an request.
//
//      m := new(dns.Msg)
//      m.SetEdns0(4096, true)
//
// Signature generation, signature verification and key generation are all supported.
// Writing a DNSSEC validating resolver is hard, if you need something like that you
// might want to use the Unbound wrapper found at github.com/miekg/unbound .
package dns

import (
	"bytes"
	"crypto"
	"crypto/dsa"
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
	INDIRECT         = 252
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
	SHA512 // Experimental
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
	SignerName  string `dns:"domain-name"`
	/* No Signature */
}

// Used for converting DNSKEY's rdata to wirefmt.
type dnskeyWireFmt struct {
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey string `dns:"base64"`
	/* Nothing is left out */
}

// KeyTag calculates the keytag (or key-id) of the DNSKEY.
func (k *DNSKEY) KeyTag() uint16 {
	if k == nil {
		return 0
	}
	var keytag int
	switch k.Algorithm {
	case RSAMD5:
		// Look at the bottom two bytes of the modules, which the last
		// item in the pubkey. We could do this faster by looking directly
		// at the base64 values. But I'm lazy.
		modulus, _ := packBase64([]byte(k.PublicKey))
		if len(modulus) > 1 {
			x, _ := unpackUint16(modulus, len(modulus)-2)
			keytag = int(x)
		}
	default:
		keywire := new(dnskeyWireFmt)
		keywire.Flags = k.Flags
		keywire.Protocol = k.Protocol
		keywire.Algorithm = k.Algorithm
		keywire.PublicKey = k.PublicKey
		wire := make([]byte, DefaultMsgSize)
		n, err := PackStruct(keywire, wire, 0)
		if err != nil {
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
func (k *DNSKEY) ToDS(h int) *DS {
	if k == nil {
		return nil
	}
	ds := new(DS)
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
	n, err := PackStruct(keywire, wire, 0)
	if err != nil {
		return nil
	}
	wire = wire[:n]

	owner := make([]byte, 255)
	off, err1 := PackDomainName(k.Hdr.Name, owner, 0, nil, false)
	if err1 != nil {
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
// There is no check if RRSet is a proper (RFC 2181) RRSet.
func (rr *RRSIG) Sign(k PrivateKey, rrset []RR) error {
	if k == nil {
		return ErrPrivKey
	}
	// s.Inception and s.Expiration may be 0 (rollover etc.), the rest must be set
	if rr.KeyTag == 0 || len(rr.SignerName) == 0 || rr.Algorithm == 0 {
		return ErrKey
	}

	rr.Hdr.Rrtype = TypeRRSIG
	rr.Hdr.Name = rrset[0].Header().Name
	rr.Hdr.Class = rrset[0].Header().Class
	rr.OrigTtl = rrset[0].Header().Ttl
	rr.TypeCovered = rrset[0].Header().Rrtype
	rr.TypeCovered = rrset[0].Header().Rrtype
	rr.Labels, _, _ = IsDomainName(rrset[0].Header().Name)

	if strings.HasPrefix(rrset[0].Header().Name, "*") {
		rr.Labels-- // wildcard, remove from label count
	}

	sigwire := new(rrsigWireFmt)
	sigwire.TypeCovered = rr.TypeCovered
	sigwire.Algorithm = rr.Algorithm
	sigwire.Labels = rr.Labels
	sigwire.OrigTtl = rr.OrigTtl
	sigwire.Expiration = rr.Expiration
	sigwire.Inception = rr.Inception
	sigwire.KeyTag = rr.KeyTag
	// For signing, lowercase this name
	sigwire.SignerName = strings.ToLower(rr.SignerName)

	// Create the desired binary blob
	signdata := make([]byte, DefaultMsgSize)
	n, err := PackStruct(sigwire, signdata, 0)
	if err != nil {
		return err
	}
	signdata = signdata[:n]
	wire := rawSignatureData(rrset, rr)
	if wire == nil {
		return ErrSigGen
	}
	signdata = append(signdata, wire...)

	var sighash []byte
	var h hash.Hash
	var ch crypto.Hash // Only need for RSA
	switch rr.Algorithm {
	case DSA, DSANSEC3SHA1:
		// Implicit in the ParameterSizes
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
	case RSAMD5:
		fallthrough // Deprecated in RFC 6725
	default:
		return ErrAlg
	}
	io.WriteString(h, string(signdata))
	sighash = h.Sum(nil)

	switch p := k.(type) {
	case *dsa.PrivateKey:
		r1, s1, err := dsa.Sign(rand.Reader, p, sighash)
		if err != nil {
			return err
		}
		signature := []byte{0x4D} // T value, here the ASCII M for Miek (not used in DNSSEC)
		signature = append(signature, r1.Bytes()...)
		signature = append(signature, s1.Bytes()...)
		rr.Signature = unpackBase64(signature)
	case *rsa.PrivateKey:
		// We can use nil as rand.Reader here (says AGL)
		signature, err := rsa.SignPKCS1v15(nil, p, ch, sighash)
		if err != nil {
			return err
		}
		rr.Signature = unpackBase64(signature)
	case *ecdsa.PrivateKey:
		r1, s1, err := ecdsa.Sign(rand.Reader, p, sighash)
		if err != nil {
			return err
		}
		signature := r1.Bytes()
		signature = append(signature, s1.Bytes()...)
		rr.Signature = unpackBase64(signature)
	default:
		// Not given the correct key
		return ErrKeyAlg
	}
	return nil
}

// Verify validates an RRSet with the signature and key. This is only the
// cryptographic test, the signature validity period must be checked separately.
// This function copies the rdata of some RRs (to lowercase domain names) for the validation to work.
func (rr *RRSIG) Verify(k *DNSKEY, rrset []RR) error {
	// First the easy checks
	if len(rrset) == 0 {
		return ErrRRset
	}
	if rr.KeyTag != k.KeyTag() {
		return ErrKey
	}
	if rr.Hdr.Class != k.Hdr.Class {
		return ErrKey
	}
	if rr.Algorithm != k.Algorithm {
		return ErrKey
	}
	if strings.ToLower(rr.SignerName) != strings.ToLower(k.Hdr.Name) {
		return ErrKey
	}
	if k.Protocol != 3 {
		return ErrKey
	}
	for _, r := range rrset {
		if r.Header().Class != rr.Hdr.Class {
			return ErrRRset
		}
		if r.Header().Rrtype != rr.TypeCovered {
			return ErrRRset
		}
	}
	// RFC 4035 5.3.2.  Reconstructing the Signed Data
	// Copy the sig, except the rrsig data
	sigwire := new(rrsigWireFmt)
	sigwire.TypeCovered = rr.TypeCovered
	sigwire.Algorithm = rr.Algorithm
	sigwire.Labels = rr.Labels
	sigwire.OrigTtl = rr.OrigTtl
	sigwire.Expiration = rr.Expiration
	sigwire.Inception = rr.Inception
	sigwire.KeyTag = rr.KeyTag
	sigwire.SignerName = strings.ToLower(rr.SignerName)
	// Create the desired binary blob
	signeddata := make([]byte, DefaultMsgSize)
	n, err := PackStruct(sigwire, signeddata, 0)
	if err != nil {
		return err
	}
	signeddata = signeddata[:n]
	wire := rawSignatureData(rrset, rr)
	if wire == nil {
		return ErrSigGen
	}
	signeddata = append(signeddata, wire...)

	sigbuf := rr.sigBuf()           // Get the binary signature data
	if rr.Algorithm == PRIVATEDNS { // PRIVATEOID
		// TODO(mg)
		// remove the domain name and assume its our
	}

	switch rr.Algorithm {
	case RSASHA1, RSASHA1NSEC3SHA1, RSASHA256, RSASHA512, RSAMD5:
		// TODO(mg): this can be done quicker, ie. cache the pubkey data somewhere??
		pubkey := k.publicKeyRSA() // Get the key
		if pubkey == nil {
			return ErrKey
		}
		// Setup the hash as defined for this alg.
		var h hash.Hash
		var ch crypto.Hash
		switch rr.Algorithm {
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
	case ECDSAP256SHA256, ECDSAP384SHA384:
		pubkey := k.publicKeyCurve()
		if pubkey == nil {
			return ErrKey
		}
		var h hash.Hash
		switch rr.Algorithm {
		case ECDSAP256SHA256:
			h = sha256.New()
		case ECDSAP384SHA384:
			h = sha512.New()
		}
		io.WriteString(h, string(signeddata))
		sighash := h.Sum(nil)
		// Split sigbuf into the r and s coordinates
		r := big.NewInt(0)
		r.SetBytes(sigbuf[:len(sigbuf)/2])
		s := big.NewInt(0)
		s.SetBytes(sigbuf[len(sigbuf)/2:])
		if ecdsa.Verify(pubkey, sighash, r, s) {
			return ErrSig
		}
		return nil
	}
	// Unknown alg
	return ErrAlg
}

// ValidityPeriod uses RFC1982 serial arithmetic to calculate
// if a signature period is valid.
func (rr *RRSIG) ValidityPeriod() bool {
	utc := time.Now().UTC().Unix()
	modi := (int64(rr.Inception) - utc) / year68
	mode := (int64(rr.Expiration) - utc) / year68
	ti := int64(rr.Inception) + (modi * year68)
	te := int64(rr.Expiration) + (mode * year68)
	return ti <= utc && utc <= te
}

// Return the signatures base64 encodedig sigdata as a byte slice.
func (s *RRSIG) sigBuf() []byte {
	sigbuf, err := packBase64([]byte(s.Signature))
	if err != nil {
		return nil
	}
	return sigbuf
}

// setPublicKeyInPrivate sets the public key in the private key.
func (k *DNSKEY) setPublicKeyInPrivate(p PrivateKey) bool {
	switch t := p.(type) {
	case *dsa.PrivateKey:
		x := k.publicKeyDSA()
		if x == nil {
			return false
		}
		t.PublicKey = *x
	case *rsa.PrivateKey:
		x := k.publicKeyRSA()
		if x == nil {
			return false
		}
		t.PublicKey = *x
	case *ecdsa.PrivateKey:
		x := k.publicKeyCurve()
		if x == nil {
			return false
		}
		t.PublicKey = *x
	}
	return true
}

// publicKeyRSA returns the RSA public key from a DNSKEY record.
func (k *DNSKEY) publicKeyRSA() *rsa.PublicKey {
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
	shift := uint64((explen - 1) * 8)
	expo := uint64(0)
	for i := int(explen - 1); i > 0; i-- {
		expo += uint64(keybuf[keyoff+i]) << shift
		shift -= 8
	}
	// Remainder
	expo += uint64(keybuf[keyoff])
	if expo > 2<<31 {
		// Larger expo than supported.
		// println("dns: F5 primes (or larger) are not supported")
		return nil
	}
	pubkey.E = int(expo)

	pubkey.N.SetBytes(keybuf[keyoff+int(explen):])
	return pubkey
}

// publicKeyCurve returns the Curve public key from the DNSKEY record.
func (k *DNSKEY) publicKeyCurve() *ecdsa.PublicKey {
	keybuf, err := packBase64([]byte(k.PublicKey))
	if err != nil {
		return nil
	}
	pubkey := new(ecdsa.PublicKey)
	switch k.Algorithm {
	case ECDSAP256SHA256:
		pubkey.Curve = elliptic.P256()
		if len(keybuf) != 64 {
			// wrongly encoded key
			return nil
		}
	case ECDSAP384SHA384:
		pubkey.Curve = elliptic.P384()
		if len(keybuf) != 96 {
			// Wrongly encoded key
			return nil
		}
	}
	pubkey.X = big.NewInt(0)
	pubkey.X.SetBytes(keybuf[:len(keybuf)/2])
	pubkey.Y = big.NewInt(0)
	pubkey.Y.SetBytes(keybuf[len(keybuf)/2:])
	return pubkey
}

func (k *DNSKEY) publicKeyDSA() *dsa.PublicKey {
	keybuf, err := packBase64([]byte(k.PublicKey))
	if err != nil {
		return nil
	}
	if len(keybuf) < 22 { // TODO: check
		return nil
	}
	t := int(keybuf[0])
	size := 64 + t*8
	pubkey := new(dsa.PublicKey)
	pubkey.Parameters.Q = big.NewInt(0)
	pubkey.Parameters.Q.SetBytes(keybuf[1:21]) // +/- 1 ?
	pubkey.Parameters.P = big.NewInt(0)
	pubkey.Parameters.P.SetBytes(keybuf[22 : 22+size])
	pubkey.Parameters.G = big.NewInt(0)
	pubkey.Parameters.G.SetBytes(keybuf[22+size+1 : 22+size*2])
	pubkey.Y = big.NewInt(0)
	pubkey.Y.SetBytes(keybuf[22+size*2+1 : 22+size*3])
	return pubkey
}

// Set the public key (the value E and N)
func (k *DNSKEY) setPublicKeyRSA(_E int, _N *big.Int) bool {
	if _E == 0 || _N == nil {
		return false
	}
	buf := exponentToBuf(_E)
	buf = append(buf, _N.Bytes()...)
	k.PublicKey = unpackBase64(buf)
	return true
}

// Set the public key for Elliptic Curves
func (k *DNSKEY) setPublicKeyCurve(_X, _Y *big.Int) bool {
	if _X == nil || _Y == nil {
		return false
	}
	buf := curveToBuf(_X, _Y)
	// Check the length of the buffer, either 64 or 92 bytes
	k.PublicKey = unpackBase64(buf)
	return true
}

// Set the public key for DSA
func (k *DNSKEY) setPublicKeyDSA(_Q, _P, _G, _Y *big.Int) bool {
	if _Q == nil || _P == nil || _G == nil || _Y == nil {
		return false
	}
	buf := dsaToBuf(_Q, _P, _G, _Y)
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

// Set the public key for X and Y for Curve. The two
// values are just concatenated.
func curveToBuf(_X, _Y *big.Int) []byte {
	buf := _X.Bytes()
	buf = append(buf, _Y.Bytes()...)
	return buf
}

// Set the public key for X and Y for Curve. The two
// values are just concatenated.
func dsaToBuf(_Q, _P, _G, _Y *big.Int) []byte {
	t := byte((len(_G.Bytes()) - 64) / 8)
	buf := []byte{t}
	buf = append(buf, _Q.Bytes()...)
	buf = append(buf, _P.Bytes()...)
	buf = append(buf, _G.Bytes()...)
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

// Return the raw signature data.
func rawSignatureData(rrset []RR, s *RRSIG) (buf []byte) {
	wires := make(wireSlice, len(rrset))
	for i, r := range rrset {
		r1 := r.copy()
		r1.Header().Ttl = s.OrigTtl
		labels := SplitDomainName(r1.Header().Name)
		// 6.2. Canonical RR Form. (4) - wildcards
		if len(labels) > int(s.Labels) {
			// Wildcard
			r1.Header().Name = "*." + strings.Join(labels[len(labels)-int(s.Labels):], ".") + "."
		}
		// RFC 4034: 6.2.  Canonical RR Form. (2) - domain name to lowercase
		r1.Header().Name = strings.ToLower(r1.Header().Name)
		// 6.2. Canonical RR Form. (3) - domain rdata to lowercase.
		//   NS, MD, MF, CNAME, SOA, MB, MG, MR, PTR,
		//   HINFO, MINFO, MX, RP, AFSDB, RT, SIG, PX, NXT, NAPTR, KX,
		//   SRV, DNAME, A6
		switch x := r.(type) {
		case *NS:
			x.Ns = strings.ToLower(x.Ns)
		case *CNAME:
			x.Target = strings.ToLower(x.Target)
		case *SOA:
			x.Ns = strings.ToLower(x.Ns)
			x.Mbox = strings.ToLower(x.Mbox)
		case *MB:
			x.Mb = strings.ToLower(x.Mb)
		case *MG:
			x.Mg = strings.ToLower(x.Mg)
		case *MR:
			x.Mr = strings.ToLower(x.Mr)
		case *PTR:
			x.Ptr = strings.ToLower(x.Ptr)
		case *MINFO:
			x.Rmail = strings.ToLower(x.Rmail)
			x.Email = strings.ToLower(x.Email)
		case *MX:
			x.Mx = strings.ToLower(x.Mx)
		case *NAPTR:
			x.Replacement = strings.ToLower(x.Replacement)
		case *KX:
			x.Exchanger = strings.ToLower(x.Exchanger)
		case *SRV:
			x.Target = strings.ToLower(x.Target)
		case *DNAME:
			x.Target = strings.ToLower(x.Target)
		}
		// 6.2. Canonical RR Form. (5) - origTTL
		wire := make([]byte, r.len(nil)*2) // TODO(mg): *2 ?
		off, err1 := PackRR(r1, wire, 0, nil, false)
		if err1 != nil {
			return nil
		}
		wire = wire[:off]
		wires[i] = wire
	}
	sort.Sort(wires)
	for _, wire := range wires {
		buf = append(buf, wire...)
	}
	return
}

// Map for algorithm names.
var AlgorithmToString = map[uint8]string{
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
	INDIRECT:         "INDIRECT",
	PRIVATEDNS:       "PRIVATEDNS",
	PRIVATEOID:       "PRIVATEOID",
}

// Map of algorithm strings.
var StringToAlgorithm = reverseInt8(AlgorithmToString)

// Map for hash names.
var HashToString = map[uint8]string{
	SHA1:   "SHA1",
	SHA256: "SHA256",
	GOST94: "GOST94",
	SHA384: "SHA384",
	SHA512: "SHA512",
}

// Map of hash strings.
var StringToHash = reverseInt8(HashToString)
