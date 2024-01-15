package dns

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// Sign signs a dns.Msg. It fills the signature with the appropriate data.
// The SIG record should have the SignerName, KeyTag, Algorithm, Inception
// and Expiration set.
func (rr *SIG) Sign(k crypto.Signer, m *Msg) ([]byte, error) {
	if k == nil {
		return nil, ErrPrivKey
	}
	if rr.KeyTag == 0 || rr.SignerName == "" || rr.Algorithm == 0 {
		return nil, ErrKey
	}

	rr.Hdr = RR_Header{Name: ".", Rrtype: TypeSIG, Class: ClassANY, Ttl: 0}
	rr.OrigTtl, rr.TypeCovered, rr.Labels = 0, 0, 0

	buf := make([]byte, m.Len()+Len(rr))
	mbuf, err := m.PackBuffer(buf)
	if err != nil {
		return nil, err
	}
	if &buf[0] != &mbuf[0] {
		panic("dns: internal error: PackBuffer re-allocated despite sufficient buffer size")
	}
	off, err := PackRR(rr, buf, len(mbuf), nil, false)
	if err != nil {
		return nil, err
	}
	buf = buf[:off:cap(buf)]

	h, cryptohash, err := hashFromAlgorithm(rr.Algorithm)
	if err != nil {
		return nil, err
	}

	// Write SIG rdata
	h.Write(buf[len(mbuf)+1+2+2+4+2:])
	// Write message
	h.Write(buf[:len(mbuf)])

	signature, err := sign(k, h.Sum(nil), cryptohash, rr.Algorithm)
	if err != nil {
		return nil, err
	}

	rr.Signature = toBase64(signature)

	buf = append(buf, signature...)
	if len(buf) > int(^uint16(0)) {
		return nil, ErrBuf
	}
	// Adjust sig data length
	rdoff := len(mbuf) + 1 + 2 + 2 + 4
	rdlen := binary.BigEndian.Uint16(buf[rdoff:])
	rdlen += uint16(len(signature))
	binary.BigEndian.PutUint16(buf[rdoff:], rdlen)
	// Adjust additional count
	adc := binary.BigEndian.Uint16(buf[10:])
	adc++
	binary.BigEndian.PutUint16(buf[10:], adc)
	return buf, nil
}

// Verify validates the message buf using the key k.
// It's assumed that buf is a valid message from which rr was unpacked.
func (rr *SIG) Verify(k *KEY, buf []byte) error {
	if k == nil {
		return ErrKey
	}
	if rr.KeyTag == 0 || rr.SignerName == "" || rr.Algorithm == 0 {
		return ErrKey
	}

	h, cryptohash, err := hashFromAlgorithm(rr.Algorithm)
	if err != nil {
		return err
	}

	s := cryptobyte.String(buf)

	var dh Header
	if !dh.unpack(&s) {
		return errTruncatedMessage
	}

	for i := 0; i < int(dh.Qdcount) && !s.Empty(); i++ {
		_, err = unpackDomainName(&s, buf)
		if err != nil {
			if errors.Is(err, errUnpackOverflow) {
				return errTruncatedMessage
			}
			return err
		}
		// Skip past Type and Class
		if !s.Skip(2 + 2) {
			return errTruncatedMessage
		}
	}

	for i, tot := 1, int(dh.Ancount)+int(dh.Nscount)+int(dh.Arcount); i < tot && !s.Empty(); i++ {
		_, err = unpackDomainName(&s, buf)
		if err != nil {
			if errors.Is(err, errUnpackOverflow) {
				return errTruncatedMessage
			}
			return err
		}
		// Skip past Type, Class, TTL, and the data
		var rdata cryptobyte.String
		if !s.Skip(2+2+4) ||
			!s.ReadUint16LengthPrefixed(&rdata) {
			return errTruncatedMessage
		}
	}

	if s.Empty() {
		return errTruncatedMessage
	}

	// offset should be just prior to SIG
	bodyend := offset(s, buf)
	// owner name SHOULD be root
	_, err = unpackDomainName(&s, buf)
	if err != nil {
		if errors.Is(err, errUnpackOverflow) {
			return errTruncatedMessage
		}
		return err
	}
	// Skip Type, Class, TTL, RDLen
	if !s.Skip(2 + 2 + 4 + 2) {
		return errTruncatedMessage
	}
	sigstart := offset(s, buf)
	var expire, incept uint32
	// Skip Type Covered, Algorithm, Labels, Original TTL
	if !s.Skip(2+1+1+4) ||
		!s.ReadUint32(&expire) ||
		!s.ReadUint32(&incept) {
		return errTruncatedMessage
	}
	now := uint32(time.Now().Unix())
	if now < incept || now > expire {
		return ErrTime
	}
	// Skip key tag
	if !s.Skip(2) {
		return errTruncatedMessage
	}
	signername, err := unpackDomainName(&s, buf)
	if err != nil {
		return err
	}
	// If key has come from the DNS name compression might
	// have mangled the case of the name
	if !strings.EqualFold(signername, k.Header().Name) {
		return &Error{err: "signer name doesn't match key name"}
	}
	h.Write(buf[sigstart:offset(s, buf)])
	h.Write(buf[:10])
	h.Write([]byte{
		byte((dh.Arcount - 1) << 8),
		byte(dh.Arcount - 1),
	})
	h.Write(buf[12:bodyend])

	hashed := h.Sum(nil)
	switch k.Algorithm {
	case RSASHA1, RSASHA256, RSASHA512:
		pk := k.publicKeyRSA()
		if pk != nil {
			return rsa.VerifyPKCS1v15(pk, cryptohash, hashed, s)
		}
	case ECDSAP256SHA256, ECDSAP384SHA384:
		pk := k.publicKeyECDSA()
		r := new(big.Int).SetBytes(s[:len(s)/2])
		s := new(big.Int).SetBytes(s[len(s)/2:])
		if pk != nil {
			if ecdsa.Verify(pk, hashed, r, s) {
				return nil
			}
			return ErrSig
		}
	case ED25519:
		pk := k.publicKeyED25519()
		if pk != nil {
			if ed25519.Verify(pk, hashed, s) {
				return nil
			}
			return ErrSig
		}
	}
	return ErrKeyAlg
}
