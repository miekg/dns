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

// CertificateToDANE converts a certificate to a hex string as used in the TLSA record.
func CertificateToDANE(selector, matchingType uint8, cert *x509.Certificate) string {
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

// Sign creates a TLSA record from an SSL certificate.
func (r *RR_TLSA) Sign(usage, selector, matchingType int, cert *x509.Certificate) error {
	r.Hdr.Rrtype = TypeTLSA
	r.Usage = uint8(usage)
	r.Selector = uint8(selector)
	r.MatchingType = uint8(matchingType)

	r.Certificate = CertificateToDANE(r.Selector, r.MatchingType, cert)
	return nil
}

// Verify verifies a TLSA record against an SSL certificate. If it is OK
// a nil error is returned.
func (r *RR_TLSA) Verify(cert *x509.Certificate) error {
	if r.Certificate == CertificateToDANE(r.Selector, r.MatchingType, cert) {
		return nil
	}
	return ErrSig // ErrSig, really?
}

// TLSAName returns the ownername of a TLSA resource record as per the
// rules specified in RFC 6698, Section 3. When an error occurs the
// empty string is returned.
func TLSAName(name, service, network string) string {
	if !IsFqdn(name) {
		return ""
	}
	p, e := net.LookupPort(network, service)
	if e != nil {
		return ""
	}
	return "_" + strconv.Itoa(p) + "_" + network + "." + name
}
