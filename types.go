// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS Resource Records Types.  See RFC 1035 and ...
//

package dns

import (
	"net"
	"strconv"
)

// Packet formats

// Wire constants.
const (
	// valid RR_Header.Rrtype and Question.qtype
	TypeA     = 1
	TypeNS    = 2
	TypeMD    = 3
	TypeMF    = 4
	TypeCNAME = 5
	TypeSOA   = 6
	TypeMB    = 7
	TypeMG    = 8
	TypeMR    = 9
	TypeNULL  = 10
	TypeWKS   = 11
	TypePTR   = 12
	TypeHINFO = 13
	TypeMINFO = 14
	TypeMX    = 15
	TypeTXT   = 16
	TypeAAAA  = 28
	TypeSRV   = 33

	// EDNS
	TypeOPT = 41

	// DNSSEC
	TypeDS         = 43
	TypeRRSIG      = 46
	TypeNSEC       = 47
	TypeDNSKEY     = 48
	TypeNSEC3      = 50
	TypeNSEC3PARAM = 51

	// valid Question.qtype only
	TypeAXFR  = 252
	TypeMAILB = 253
	TypeMAILA = 254
	TypeALL   = 255

	// valid Question.qclass
	ClassINET   = 1
	ClassCSNET  = 2
	ClassCHAOS  = 3
	ClassHESIOD = 4
	ClassANY    = 255

	// Msg.rcode
	RcodeSuccess        = 0
	RcodeFormatError    = 1
	RcodeServerFailure  = 2
	RcodeNameError      = 3
	RcodeNotImplemented = 4
	RcodeRefused        = 5
)

// The wire format for the DNS packet header.
type Header struct {
	Id                                 uint16
	Bits                               uint16
	Qdcount, Ancount, Nscount, Arcount uint16
}

const (
	// Header.Bits
	_QR = 1 << 15 // query/response (response=1)
	_AA = 1 << 10 // authoritative
	_TC = 1 << 9  // truncated
	_RD = 1 << 8  // recursion desired
	_RA = 1 << 7  // recursion available
	// _AD = 1 << ? // authenticated data
	// _CD = 1 << ? // checking disabled
)

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

// DNS queries.
type Question struct {
	Name   string "domain-name" // "domain-name" specifies encoding; see packers below
	Qtype  uint16
	Qclass uint16
}

// Rcode needs some setting and getting work for _z and _version
type Edns struct {
	Name     string "domain-name"
	Opt      uint16 // was type
	UDPSize  uint16 // was class
	Rcode    uint32 // was TTL
	Rdlength uint16
}


func (q *Question) String() string {
	// prefix with ; (as in dig)
	s := ";" + q.Name + "\t"
	s = s + class_str[q.Qclass] + "\t"
	s = s + rr_str[q.Qtype]
	return s
}

// DNS responses (resource records).
// There are many types of messages,
// but they all share the same header.
type RR_Header struct {
	Name     string "domain-name"
	Rrtype   uint16
	Class    uint16
	Ttl      uint32
	Rdlength uint16 // length of data after header
}

func (h *RR_Header) Header() *RR_Header {
	return h
}

func (h *RR_Header) String() string {
	var s string
	if len(h.Name) == 0 {
		s = ".\t"
	} else {
		s = h.Name + "\t"
	}
	s = s + strconv.Itoa(int(h.Ttl)) + "\t" // why no strconv.Uint16??
	s = s + class_str[h.Class] + "\t"
	s = s + rr_str[h.Rrtype] + "\t"
	return s
}

type RR interface {
	Header() *RR_Header
	String() string
}

// Specific DNS RR formats for each query type.

type RR_CNAME struct {
	Hdr   RR_Header
	Cname string "domain-name"
}

func (rr *RR_CNAME) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_CNAME) String() string {
	return rr.Hdr.String() + rr.Cname
}

type RR_HINFO struct {
	Hdr RR_Header
	Cpu string
	Os  string
}

func (rr *RR_HINFO) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_HINFO) String() string {
	return rr.Hdr.String() + rr.Cpu + " " + rr.Os
}

type RR_MB struct {
	Hdr RR_Header
	Mb  string "domain-name"
}

func (rr *RR_MB) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_MB) String() string {
	return rr.Hdr.String() + rr.Mb
}

type RR_MG struct {
	Hdr RR_Header
	Mg  string "domain-name"
}

func (rr *RR_MG) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_MG) String() string {
	return rr.Hdr.String() + rr.Mg
}

type RR_MINFO struct {
	Hdr   RR_Header
	Rmail string "domain-name"
	Email string "domain-name"
}

func (rr *RR_MINFO) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_MINFO) String() string {
	return rr.Hdr.String() + rr.Rmail + " " + rr.Email
}

type RR_MR struct {
	Hdr RR_Header
	Mr  string "domain-name"
}

func (rr *RR_MR) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_MR) String() string {
	return rr.Hdr.String() + rr.Mr
}

type RR_MX struct {
	Hdr  RR_Header
	Pref uint16
	Mx   string "domain-name"
}

func (rr *RR_MX) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_MX) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Pref)) + " " + rr.Mx
}

type RR_NS struct {
	Hdr RR_Header
	Ns  string "domain-name"
}

func (rr *RR_NS) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_NS) String() string {
	return rr.Hdr.String() + rr.Ns
}

type RR_PTR struct {
	Hdr RR_Header
	Ptr string "domain-name"
}

func (rr *RR_PTR) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_PTR) String() string {
	return rr.Hdr.String() + rr.Ptr
}

type RR_SOA struct {
	Hdr     RR_Header
	Ns      string "domain-name"
	Mbox    string "domain-name"
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minttl  uint32
}

func (rr *RR_SOA) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_SOA) String() string {
	return rr.Hdr.String() + rr.Ns + " " + rr.Mbox +
		" " + strconv.Itoa(int(rr.Serial)) +
		" " + strconv.Itoa(int(rr.Refresh)) +
		" " + strconv.Itoa(int(rr.Retry)) +
		" " + strconv.Itoa(int(rr.Expire)) +
		" " + strconv.Itoa(int(rr.Minttl))
}

type RR_TXT struct {
	Hdr RR_Header
	Txt string // not domain name
}

func (rr *RR_TXT) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_TXT) String() string {
	return rr.Hdr.String() + "\"" + rr.Txt + "\""
}

type RR_SRV struct {
	Hdr      RR_Header
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string "domain-name"
}

func (rr *RR_SRV) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_SRV) String() string {
	return rr.Hdr.String() +
		strconv.Itoa(int(rr.Priority)) + " " +
		strconv.Itoa(int(rr.Weight)) + " " +
		strconv.Itoa(int(rr.Port)) + " " + rr.Target
}

type RR_A struct {
	Hdr RR_Header
	A   net.IP "ipv4"
}

func (rr *RR_A) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_A) String() string {
	return rr.Hdr.String() + rr.A.String()
}

type RR_AAAA struct {
	Hdr  RR_Header
	AAAA net.IP "ipv6"
}

func (rr *RR_AAAA) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_AAAA) String() string {
	return rr.Hdr.String() + rr.AAAA.String()
}

// DNSSEC types
type RR_RRSIG struct {
	Hdr RR_Header
}

func (rr *RR_RRSIG) Header() *RR_Header {
	return &rr.Hdr
}
func (rr *RR_RRSIG) String() string {
	return "BLAH"
}

type RR_NSEC struct {
	Hdr RR_Header
}

func (rr *RR_NSEC) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_NSEC) String() string {
	return "BLAH"
}

type RR_DS struct {
	Hdr        RR_Header
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string "hex"
}

func (rr *RR_DS) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_DS) String() string {
	return rr.Hdr.String() +
		" " + strconv.Itoa(int(rr.KeyTag)) +
		" " + alg_str[rr.Algorithm] +
		" " + strconv.Itoa(int(rr.DigestType)) +
		" " + rr.Digest
}

type RR_DNSKEY struct {
	Hdr       RR_Header
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PubKey    string "base64"
}

func (rr *RR_DNSKEY) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_DNSKEY) String() string {
	return rr.Hdr.String() +
		" " + strconv.Itoa(int(rr.Flags)) +
		" " + strconv.Itoa(int(rr.Protocol)) +
		" " + alg_str[rr.Algorithm] +
		" " + rr.PubKey // encoding/base64
}

type RR_NSEC3 struct {
	Hdr RR_Header
}

func (rr *RR_NSEC3) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_NSEC3) String() string {
	return "BLAH"
}

type RR_NSEC3PARAM struct {
	Hdr RR_Header
}

func (rr *RR_NSEC3PARAM) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_NSEC3PARAM) String() string {
	return "BLAH"
}

// Map of constructors for each RR wire type.
var rr_mk = map[int]func() RR{
	TypeCNAME:      func() RR { return new(RR_CNAME) },
	TypeHINFO:      func() RR { return new(RR_HINFO) },
	TypeMB:         func() RR { return new(RR_MB) },
	TypeMG:         func() RR { return new(RR_MG) },
	TypeMINFO:      func() RR { return new(RR_MINFO) },
	TypeMR:         func() RR { return new(RR_MR) },
	TypeMX:         func() RR { return new(RR_MX) },
	TypeNS:         func() RR { return new(RR_NS) },
	TypePTR:        func() RR { return new(RR_PTR) },
	TypeSOA:        func() RR { return new(RR_SOA) },
	TypeTXT:        func() RR { return new(RR_TXT) },
	TypeSRV:        func() RR { return new(RR_SRV) },
	TypeA:          func() RR { return new(RR_A) },
	TypeAAAA:       func() RR { return new(RR_AAAA) },
	TypeDS:         func() RR { return new(RR_DS) },
	TypeRRSIG:      func() RR { return new(RR_RRSIG) },
	TypeNSEC:       func() RR { return new(RR_NSEC) },
	TypeDNSKEY:     func() RR { return new(RR_DNSKEY) },
	TypeNSEC3:      func() RR { return new(RR_NSEC3) },
	TypeNSEC3PARAM: func() RR { return new(RR_NSEC3PARAM) },
}

// Map of strings for each RR wire type.
var rr_str = map[uint16]string{
	TypeCNAME:      "CNAME",
	TypeHINFO:      "HINFO",
	TypeMB:         "MB",
	TypeMG:         "MG",
	TypeMINFO:      "MINFO",
	TypeMR:         "MR",
	TypeMX:         "MX",
	TypeNS:         "NS",
	TypePTR:        "PTR",
	TypeSOA:        "SOA",
	TypeTXT:        "TXT",
	TypeSRV:        "SRV",
	TypeA:          "A",
	TypeAAAA:       "AAAA",
	TypeDS:         "DS",
	TypeRRSIG:      "RRSIG",
	TypeNSEC:       "NSEC",
	TypeDNSKEY:     "DNSKEY",
	TypeNSEC3:      "NSEC3",
	TypeNSEC3PARAM: "NSEC3PARAM",
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
