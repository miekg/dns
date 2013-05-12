// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"crypto/sha1"
	"hash"
	"io"
	"strings"
)

const (
	_ = iota
	_NSEC3_NXDOMAIN
	_NSEC3_NODATA
)

type saltWireFmt struct {
	Salt string `dns:"size-hex"`
}

// HashName hashes a string (label) according to RFC 5155. It returns the hashed string.
func HashName(label string, ha uint8, iter uint16, salt string) string {
	saltwire := new(saltWireFmt)
	saltwire.Salt = salt
	wire := make([]byte, DefaultMsgSize)
	n, err := PackStruct(saltwire, wire, 0)
	if err != nil {
		return ""
	}
	wire = wire[:n]
	name := make([]byte, 255)
	off, err := PackDomainName(strings.ToLower(label), name, 0, nil, false)
	if err != nil {
		return ""
	}
	name = name[:off]
	var s hash.Hash
	switch ha {
	case SHA1:
		s = sha1.New()
	default:
		return ""
	}

	// k = 0
	name = append(name, wire...)
	io.WriteString(s, string(name))
	nsec3 := s.Sum(nil)
	// k > 0
	for k := uint16(0); k < iter; k++ {
		s.Reset()
		nsec3 = append(nsec3, wire...)
		io.WriteString(s, string(nsec3))
		nsec3 = s.Sum(nil)
	}
	return unpackBase32(nsec3)
}

// Implement the HashNames method of Denialer
func (rr *NSEC3) HashNames(domain string) {
	rr.Header().Name = strings.ToLower(HashName(rr.Header().Name, rr.Hash, rr.Iterations, rr.Salt)) + "." + domain
	rr.NextDomain = HashName(rr.NextDomain, rr.Hash, rr.Iterations, rr.Salt)
}

// Implement the Match method of Denialer
func (rr *NSEC3) Match(domain string) bool {
	return strings.ToUpper(SplitLabels(rr.Header().Name)[0]) == strings.ToUpper(HashName(domain, rr.Hash, rr.Iterations, rr.Salt))
}

// Implement the Match method of Denialer
func (rr *NSEC) Match(domain string) bool {
	return strings.ToUpper(rr.Header().Name) == strings.ToUpper(domain)
}

func (rr *NSEC3) MatchType(rrtype uint16) bool {
	for _, t := range rr.TypeBitMap {
		if t == rrtype {
			return true
		}
		if t > rrtype {
			return false
		}
	}
	return false
}

func (rr *NSEC) MatchType(rrtype uint16) bool {
	for _, t := range rr.TypeBitMap {
		if t == rrtype {
			return true
		}
		if t > rrtype {
			return false
		}
	}
	return false
}

// Cover checks if domain is covered by the NSEC3 record. Domain must be given in plain text (i.e. not hashed)
// TODO(mg): this doesn't loop around
// TODO(mg): make a CoverHashed variant?
func (rr *NSEC3) Cover(domain string) bool {
	hashdom := strings.ToUpper(HashName(domain, rr.Hash, rr.Iterations, rr.Salt))
	nextdom := strings.ToUpper(rr.NextDomain)
	owner := strings.ToUpper(SplitLabels(rr.Header().Name)[0])                                                                     // The hashed part
	apex := strings.ToUpper(HashName(strings.Join(SplitLabels(rr.Header().Name)[1:], "."), rr.Hash, rr.Iterations, rr.Salt)) + "." // The name of the zone
	// if nextdomain equals the apex, it is considered The End. So in that case hashdom is always less then nextdomain
	if hashdom > owner && nextdom == apex {
		return true
	}

	if hashdom > owner && hashdom <= nextdom {
		return true
	}

	return false
}

// Cover checks if domain is covered by the NSEC record. Domain must be given in plain text.
func (rr *NSEC) Cover(domain string) bool {
	return false
}
