// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Extended and bugfixes by Miek Gieben

// Basic usage pattern for creating new Resource Record:
//
// r := new(RR_TXT)
// r.Hdr = RR_Header{Name: "a.miek.nl", Rrtype: TypeTXT, Class: ClassINET, Ttl: 3600}
// r.TXT = "This is the content of the TXT record"
//
package dns

import (
	"net"
	"strconv"
	"strings"
	"time"
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
	TypeLOC   = 29
	TypeSRV   = 33
	TypeNAPTR = 35
        TypeDNAME = 39

	// EDNS
	TypeOPT = 41

	TypeSIG        = 24
	TypeKEY        = 25
	TypeNXT        = 30
	TypeDS         = 43
	TypeSSHFP      = 44
	TypeRRSIG      = 46
	TypeNSEC       = 47
	TypeDNSKEY     = 48
	TypeNSEC3      = 50
	TypeNSEC3PARAM = 51

	TypeTKEY = 249
	TypeTSIG = 250
	// valid Question.qtype only
	TypeIXFR  = 251
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
	RcodeYXDomain       = 6
	RcodeYXRrset        = 7
	RcodeNXRrset        = 8
	RcodeNotAuth        = 9
	RcodeNotZone        = 10
	// Tsig errors
	TsigBadSig  = 16
	TsigBadKey  = 17
	TsigBadTime = 18
	// Tkey errors
	TkeyBadMode = 19
	TkeyBadName = 20
	TKeyBadAlg  = 21

	// Opcode
	OpcodeQuery  = 0
	OpcodeIQuery = 1
	OpcodeStatus = 2
	// There is no 3
	OpcodeNotify = 4
	OpcodeUpdate = 5
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
	_Z  = 1 << 6  // Z
	_AD = 1 << 5  // authticated data
	_CD = 1 << 4  // checking disabled
)

// DNS queries.
type Question struct {
	Name   string "domain-name" // "domain-name" specifies encoding; see packers below
	Qtype  uint16
	Qclass uint16
}

func (q *Question) String() string {
	// prefix with ; (as in dig)
	s := ";" + q.Name + "\t"
	s = s + Class_str[q.Qclass] + "\t"
	s = s + Rr_str[q.Qtype]
	return s
}

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

type RR_NAPTR struct {
	Hdr         RR_Header
	Order       uint16
	Preference  uint16
	Flags       string
	Service     string
	Regexp      string
	Replacement string "domain-name"
}

func (rr *RR_NAPTR) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_NAPTR) String() string {
	return rr.Hdr.String() +
		strconv.Itoa(int(rr.Order)) + " " +
		strconv.Itoa(int(rr.Preference)) + " " +
		"\"" + rr.Flags + "\" " +
		"\"" + rr.Service + "\" " +
		"\"" + rr.Regexp + "\" " +
		rr.Replacement
}

// RFC 2672
type RR_DNAME struct {
	Hdr         RR_Header
	Target      string "domain-name"
}

func (rr *RR_DNAME) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_DNAME) String() string {
	return rr.Hdr.String() + " " + rr.Target
}

type RR_A struct {
	Hdr RR_Header
	A   net.IP "A"
}

func (rr *RR_A) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_A) String() string {
	return rr.Hdr.String() + rr.A.String()
}

type RR_AAAA struct {
	Hdr  RR_Header
	AAAA net.IP "AAAA"
}

func (rr *RR_AAAA) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_AAAA) String() string {
	return rr.Hdr.String() + rr.AAAA.String()
}

type RR_LOC struct {
	Hdr       RR_Header
	Version   uint8
	Size      uint8
	HorizPre  uint8
	VertPre   uint8
	Latitude  uint32
	Longitude uint32
	Altitude  uint32
}

func (rr *RR_LOC) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_LOC) String() string {
        // Version is not shown
	return rr.Hdr.String() + "TODO"
}

// DNSSEC types
type RR_RRSIG struct {
	Hdr         RR_Header
	TypeCovered uint16
	Algorithm   uint8
	Labels      uint8
	OrigTtl     uint32
	Expiration  uint32
	Inception   uint32
	KeyTag      uint16
	SignerName  string "domain-name"
	Signature   string "base64"
}

func (rr *RR_RRSIG) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_RRSIG) String() string {
	return rr.Hdr.String() + Rr_str[rr.TypeCovered] +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + strconv.Itoa(int(rr.Labels)) +
		" " + strconv.Itoa(int(rr.OrigTtl)) +
		" " + timeToDate(rr.Expiration) +
		" " + timeToDate(rr.Inception) +
		" " + strconv.Itoa(int(rr.KeyTag)) +
		" " + rr.SignerName +
		" " + rr.Signature
}

type RR_NSEC struct {
	Hdr        RR_Header
	NextDomain string   "domain-name"
	TypeBitMap []uint16 "NSEC"
}

func (rr *RR_NSEC) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_NSEC) String() string {
	s := rr.Hdr.String() + rr.NextDomain
	for i := 0; i < len(rr.TypeBitMap); i++ {
		// Check if map exists, otherwise "TYPE" + strcov.Itoa(int(rr.TypeBitMap[i]))
		s = s + " " + Rr_str[rr.TypeBitMap[i]]
	}
	return s
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
	return rr.Hdr.String() + strconv.Itoa(int(rr.KeyTag)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + strconv.Itoa(int(rr.DigestType)) +
		" " + strings.ToUpper(rr.Digest)
}


type RR_SSHFP struct {
	Hdr         RR_Header
	Algorithm   uint8
	Type        uint8
	FingerPrint string "hex"
}

func (rr *RR_SSHFP) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_SSHFP) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Algorithm)) +
		" " + strconv.Itoa(int(rr.Type)) +
		" " + strings.ToUpper(rr.FingerPrint)
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
	return rr.Hdr.String() + strconv.Itoa(int(rr.Flags)) +
		" " + strconv.Itoa(int(rr.Protocol)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + rr.PubKey
}

type RR_NSEC3 struct {
	Hdr        RR_Header
	Hash       uint8
	Flags      uint8
	Iterations uint16
	SaltLength uint8
	Salt       string "hex"
	HashLength uint8
	NextDomain string   "domain-name"
	TypeBitMap []uint16 "NSEC"
}

func (rr *RR_NSEC3) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_NSEC3) String() string {
	s := rr.Hdr.String()
	s += strconv.Itoa(int(rr.Hash)) +
		" " + strconv.Itoa(int(rr.Flags)) +
		" " + strconv.Itoa(int(rr.Iterations)) +
		" " + strings.ToUpper(rr.Salt) +
		" " + rr.NextDomain // must base32?
	for i := 0; i < len(rr.TypeBitMap); i++ {
		// Check if map exists, otherwise "TYPE" + strcov.Itoa(int(rr.TypeBitMap[i]))
		s = s + " " + Rr_str[rr.TypeBitMap[i]]
	}
	return s
}

type RR_NSEC3PARAM struct {
	Hdr        RR_Header
	Hash       uint8
	Flags      uint8
	Iterations uint16
	SaltLength uint8
	Salt       string "hex"
}

func (rr *RR_NSEC3PARAM) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_NSEC3PARAM) String() string {
	s := rr.Hdr.String()
        s += strconv.Itoa(int(rr.Hash)) +
                " " + strconv.Itoa(int(rr.Flags)) +
                " " + strconv.Itoa(int(rr.Iterations)) +
                " " + strings.ToUpper(rr.Salt)
        return s
}

type RR_TKEY struct {
	Hdr        RR_Header
	Algorithm  string "domain-name"
	Inception  uint32
	Expiration uint32
	Mode       uint16
	Error      uint16
	KeySize    uint16
	Key        string
	Otherlen   uint16
	OtherData  string
}

func (rr *RR_TKEY) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_TKEY) String() string {
	// It has no presentation format
	return ""
}

// Translate the RRSIG's incep. and expir. time to the correct date.
// Taking into account serial arithmetic (RFC 1982)
func timeToDate(t uint32) string {
	utc := time.UTC().Seconds()
	mod := (int64(t) - utc) / Year68

	// If needed assume wrap around(s)
	ti := time.SecondsToUTC(int64(t) + (mod * Year68)) // abs()? TODO
	return ti.Format("20060102030405")
}

// Translate the TSIG time signed into a date. There is no
// need for RFC1982 calculations as this date is 48 bits
func tsigTimeToDate(t uint64) string {
	// only use the lower 48 bits, TODO(mg), check for 48 bit size
	ti := time.SecondsToUTC(int64(t))
	return ti.Format("20060102030405")
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
	TypeNAPTR:      func() RR { return new(RR_NAPTR) },
	TypeDNAME:      func() RR { return new(RR_DNAME) },
	TypeA:          func() RR { return new(RR_A) },
	TypeAAAA:       func() RR { return new(RR_AAAA) },
	TypeLOC:        func() RR { return new(RR_LOC) },
	TypeOPT:        func() RR { return new(RR_OPT) },
	TypeDS:         func() RR { return new(RR_DS) },
	TypeSSHFP:      func() RR { return new(RR_SSHFP) },
	TypeRRSIG:      func() RR { return new(RR_RRSIG) },
	TypeNSEC:       func() RR { return new(RR_NSEC) },
	TypeDNSKEY:     func() RR { return new(RR_DNSKEY) },
	TypeNSEC3:      func() RR { return new(RR_NSEC3) },
	TypeNSEC3PARAM: func() RR { return new(RR_NSEC3PARAM) },
	TypeTKEY:       func() RR { return new(RR_TKEY) },
	TypeTSIG:       func() RR { return new(RR_TSIG) },
}
