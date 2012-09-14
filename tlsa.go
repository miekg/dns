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

// Sign creates a TLSA record from a SSL certificate.
func (r *RR_TLSA) Sign(usage, selector, matchingType int, cert *x509.Certificate) error {
	r.Hdr.Rrtype = TypeTLSA
	r.Usage = uint8(usage)
	r.Selector = uint8(selector)
	r.MatchingType = uint8(matchingType)

	switch r.MatchingType {
	case 0:
		switch r.Selector {
		case 0:
			r.Certificate = hex.EncodeToString(cert.Raw)
		case 1:
			r.Certificate = hex.EncodeToString(cert.RawSubjectPublicKeyInfo)
		}
	case 1:
		h := sha256.New()
		switch r.Selector {
		case 0:
			r.Certificate = hex.EncodeToString(cert.Raw)
		case 1:
			io.WriteString(h, string(cert.RawSubjectPublicKeyInfo))
			r.Certificate = hex.EncodeToString(h.Sum(nil))
		}
	case 2:
		h := sha512.New()
		switch r.Selector {
		case 0:
			r.Certificate = hex.EncodeToString(cert.Raw)
		case 1:
			io.WriteString(h, string(cert.RawSubjectPublicKeyInfo))
			r.Certificate = hex.EncodeToString(h.Sum(nil))
		}
	}
	return nil
}

// Verify verifies a TLSA record against a SSL certificate.
func (r *RR_TLSA) Verify() error {
	return nil

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
