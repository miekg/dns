package dns

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net"
	"strconv"
)

// TLSA support functions

// certToTLSACert returns the hex data suitable for inclusion in a TLSA record
func certToTLSACert(selector, matchingType uint8, cert *x509.Certificate) string {
	switch matchingType {
	case 0:
		switch selector {
		case 0:
			return hex.EncodeToString(cert.Raw)
		case 1:
			return hex.EncodeToString(cert.RawSubjectPublicKeyInfo)
		}
	case 1:
		h := sha256.New()
		switch selector {
		case 0:
			return hex.EncodeToString(cert.Raw)
		case 1:
			io.WriteString(h, string(cert.RawSubjectPublicKeyInfo))
			return hex.EncodeToString(h.Sum(nil))
		}
	case 2:
		h := sha512.New()
		switch selector {
		case 0:
			return hex.EncodeToString(cert.Raw)
		case 1:
			io.WriteString(h, string(cert.RawSubjectPublicKeyInfo))
			return hex.EncodeToString(h.Sum(nil))
		}
	}
	return ""
}

// Sign creates a TLSA record from a SSL certificate.
func (r *RR_TLSA) Sign(usage, selector, matchingType int, cert *x509.Certificate) error {
	r.Hdr.Rrtype = TypeTLSA
	r.Usage = uint8(usage)
	r.Selector = uint8(selector)
	r.MatchingType = uint8(matchingType)
	// Checks on the value!?

	r.Certificate = certToTLSACert(r.Selector, r.MatchingType, cert)
	return nil
}

// Verify verifies a TLSA record against a SSL certificate. If it is OK
// a nil error is returned.
func (r *RR_TLSA) Verify(cert *x509.Certificate) error {
	if r.Certificate == certToTLSACert(r.Selector, r.MatchingType, cert) {
		return nil
	}
	return ErrSig	// ErrSig, really?
}

// Name set the ownername of the TLSA record according to the
// rules specified in RFC 6698, Section 3.
func (r *RR_TLSA) Name(name, service, network string) bool {
	if !IsFqdn(name) {
		return false
	}
	p, e := net.LookupPort(network, service)
	if e != nil {
		return false
	}
	r.Hdr.Name = "_" + strconv.Itoa(p) + "_" + network + "." + name
	return true
}
