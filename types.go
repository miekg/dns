// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Extensions of the original work are copyright (c) 2011 Miek Gieben

package dns

import (
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type (
	Type  uint16
	Class uint16
)

// Packet formats

// Wire constants and supported types.
const (
	// valid RR_Header.Rrtype and Question.qtype
	TypeNone       uint16 = 0
	TypeA          uint16 = 1
	TypeNS         uint16 = 2
	TypeMD         uint16 = 3
	TypeMF         uint16 = 4
	TypeCNAME      uint16 = 5
	TypeSOA        uint16 = 6
	TypeMB         uint16 = 7
	TypeMG         uint16 = 8
	TypeMR         uint16 = 9
	TypeNULL       uint16 = 10
	TypeWKS        uint16 = 11
	TypePTR        uint16 = 12
	TypeHINFO      uint16 = 13
	TypeMINFO      uint16 = 14
	TypeMX         uint16 = 15
	TypeTXT        uint16 = 16
	TypeRP         uint16 = 17
	TypeAFSDB      uint16 = 18
	TypeX25        uint16 = 19
	TypeISDN       uint16 = 20
	TypeRT         uint16 = 21
	TypeSIG        uint16 = 24
	TypeKEY        uint16 = 25
	TypeAAAA       uint16 = 28
	TypeLOC        uint16 = 29
	TypeNXT        uint16 = 30
	TypeSRV        uint16 = 33
	TypeATMA       uint16 = 34
	TypeNAPTR      uint16 = 35
	TypeKX         uint16 = 36
	TypeCERT       uint16 = 37
	TypeDNAME      uint16 = 39
	TypeOPT        uint16 = 41 // EDNS
	TypeDS         uint16 = 43
	TypeSSHFP      uint16 = 44
	TypeIPSECKEY   uint16 = 45
	TypeRRSIG      uint16 = 46
	TypeNSEC       uint16 = 47
	TypeDNSKEY     uint16 = 48
	TypeDHCID      uint16 = 49
	TypeNSEC3      uint16 = 50
	TypeNSEC3PARAM uint16 = 51
	TypeTLSA       uint16 = 52
	TypeHIP        uint16 = 55
	TypeNINFO      uint16 = 56
	TypeRKEY       uint16 = 57
	TypeTALINK     uint16 = 58
	TypeCDS        uint16 = 59
	TypeSPF        uint16 = 99
	TypeUINFO      uint16 = 100
	TypeUID        uint16 = 101
	TypeGID        uint16 = 102
	TypeUNSPEC     uint16 = 103
	TypeNID        uint16 = 104
	TypeL32        uint16 = 105
	TypeL64        uint16 = 106
	TypeLP         uint16 = 107
	TypeEUI48      uint16 = 108
	TypeEUI64      uint16 = 109

	TypeTKEY uint16 = 249
	TypeTSIG uint16 = 250
	// valid Question.Qtype only
	TypeIXFR  uint16 = 251
	TypeAXFR  uint16 = 252
	TypeMAILB uint16 = 253
	TypeMAILA uint16 = 254
	TypeANY   uint16 = 255

	TypeURI uint16 = 256
	TypeCAA uint16 = 257
	TypeTA  uint16 = 32768
	TypeDLV uint16 = 32769

	// valid Question.Qclass
	ClassINET   = 1
	ClassCSNET  = 2
	ClassCHAOS  = 3
	ClassHESIOD = 4
	ClassNONE   = 254
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
	RcodeBadSig         = 16 // TSIG
	RcodeBadVers        = 16 // EDNS0
	RcodeBadKey         = 17
	RcodeBadTime        = 18
	RcodeBadMode        = 19 // TKEY
	RcodeBadName        = 20
	RcodeBadAlg         = 21
	RcodeBadTrunc       = 22 // TSIG

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

	_LOC_EQUATOR = 1 << 31 // RFC 1876, Section 2.
)

// DNS queries.
type Question struct {
	Name   string `dns:"cdomain-name"` // "cdomain-name" specifies encoding (and may be compressed)
	Qtype  uint16
	Qclass uint16
}

func (q *Question) String() (s string) {
	// prefix with ; (as in dig)
	if len(q.Name) == 0 {
		s = ";.\t" // root label
	} else {
		s = ";" + q.Name + "\t"
	}
	s += Class(q.Qclass).String() + "\t"
	s += " " + Type(q.Qtype).String()
	return s
}

func (q *Question) len() int {
	l := len(q.Name) + 1
	return l + 4
}

type ANY struct {
	Hdr RR_Header
	// Does not have any rdata
}

func (rr *ANY) Header() *RR_Header { return &rr.Hdr }
func (rr *ANY) copy() RR           { return &ANY{*rr.Hdr.copyHeader()} }
func (rr *ANY) String() string     { return rr.Hdr.String() }
func (rr *ANY) len() int           { return rr.Hdr.len() }

type CNAME struct {
	Hdr    RR_Header
	Target string `dns:"cdomain-name"`
}

func (rr *CNAME) Header() *RR_Header { return &rr.Hdr }
func (rr *CNAME) copy() RR           { return &CNAME{*rr.Hdr.copyHeader(), rr.Target} }
func (rr *CNAME) String() string     { return rr.Hdr.String() + rr.Target }
func (rr *CNAME) len() int           { return rr.Hdr.len() + len(rr.Target) + 1 }

type HINFO struct {
	Hdr RR_Header
	Cpu string
	Os  string
}

func (rr *HINFO) Header() *RR_Header { return &rr.Hdr }
func (rr *HINFO) copy() RR           { return &HINFO{*rr.Hdr.copyHeader(), rr.Cpu, rr.Os} }
func (rr *HINFO) String() string     { return rr.Hdr.String() + rr.Cpu + " " + rr.Os }
func (rr *HINFO) len() int           { return rr.Hdr.len() + len(rr.Cpu) + len(rr.Os) }

type MB struct {
	Hdr RR_Header
	Mb  string `dns:"cdomain-name"`
}

func (rr *MB) Header() *RR_Header { return &rr.Hdr }
func (rr *MB) copy() RR           { return &MB{*rr.Hdr.copyHeader(), rr.Mb} }

func (rr *MB) String() string { return rr.Hdr.String() + rr.Mb }
func (rr *MB) len() int       { return rr.Hdr.len() + len(rr.Mb) + 1 }

type MG struct {
	Hdr RR_Header
	Mg  string `dns:"cdomain-name"`
}

func (rr *MG) Header() *RR_Header { return &rr.Hdr }
func (rr *MG) copy() RR           { return &MG{*rr.Hdr.copyHeader(), rr.Mg} }

func (rr *MG) String() string {
	return rr.Hdr.String() + rr.Mg
}

func (rr *MG) len() int {
	l := len(rr.Mg) + 1
	return rr.Hdr.len() + l
}

type MINFO struct {
	Hdr   RR_Header
	Rmail string `dns:"cdomain-name"`
	Email string `dns:"cdomain-name"`
}

func (rr *MINFO) Header() *RR_Header { return &rr.Hdr }
func (rr *MINFO) copy() RR           { return &MINFO{*rr.Hdr.copyHeader(), rr.Rmail, rr.Email} }

func (rr *MINFO) String() string {
	return rr.Hdr.String() + rr.Rmail + " " + rr.Email
}

func (rr *MINFO) len() int {
	l := len(rr.Rmail) + 1
	n := len(rr.Email) + 1
	return rr.Hdr.len() + l + n
}

type MR struct {
	Hdr RR_Header
	Mr  string `dns:"cdomain-name"`
}

func (rr *MR) Header() *RR_Header { return &rr.Hdr }
func (rr *MR) copy() RR           { return &MR{*rr.Hdr.copyHeader(), rr.Mr} }

func (rr *MR) String() string {
	return rr.Hdr.String() + rr.Mr
}

func (rr *MR) len() int {
	l := len(rr.Mr) + 1
	return rr.Hdr.len() + l
}

type MF struct {
	Hdr RR_Header
	Mf  string `dns:"cdomain-name"`
}

func (rr *MF) Header() *RR_Header { return &rr.Hdr }
func (rr *MF) copy() RR           { return &MF{*rr.Hdr.copyHeader(), rr.Mf} }

func (rr *MF) String() string {
	return rr.Hdr.String() + " " + rr.Mf
}

func (rr *MF) len() int {
	return rr.Hdr.len() + len(rr.Mf) + 1
}

type MD struct {
	Hdr RR_Header
	Md  string `dns:"cdomain-name"`
}

func (rr *MD) Header() *RR_Header { return &rr.Hdr }
func (rr *MD) copy() RR           { return &MD{*rr.Hdr.copyHeader(), rr.Md} }

func (rr *MD) String() string {
	return rr.Hdr.String() + " " + rr.Md
}

func (rr *MD) len() int {
	return rr.Hdr.len() + len(rr.Md) + 1
}

type MX struct {
	Hdr        RR_Header
	Preference uint16
	Mx         string `dns:"cdomain-name"`
}

func (rr *MX) Header() *RR_Header { return &rr.Hdr }
func (rr *MX) copy() RR           { return &MX{*rr.Hdr.copyHeader(), rr.Preference, rr.Mx} }

func (rr *MX) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Preference)) + " " + rr.Mx
}

func (rr *MX) len() int {
	l := len(rr.Mx) + 1
	return rr.Hdr.len() + l + 2
}

type AFSDB struct {
	Hdr      RR_Header
	Subtype  uint16
	Hostname string `dns:"cdomain-name"`
}

func (rr *AFSDB) Header() *RR_Header { return &rr.Hdr }
func (rr *AFSDB) copy() RR           { return &AFSDB{*rr.Hdr.copyHeader(), rr.Subtype, rr.Hostname} }

func (rr *AFSDB) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Subtype)) + " " + rr.Hostname
}

func (rr *AFSDB) len() int {
	l := len(rr.Hostname) + 1
	return rr.Hdr.len() + l + 2
}

type X25 struct {
	Hdr         RR_Header
	PSDNAddress string
}

func (rr *X25) Header() *RR_Header { return &rr.Hdr }
func (rr *X25) copy() RR           { return &X25{*rr.Hdr.copyHeader(), rr.PSDNAddress} }

func (rr *X25) String() string {
	return rr.Hdr.String() + rr.PSDNAddress
}

func (rr *X25) len() int {
	return rr.Hdr.len() + len(rr.PSDNAddress)
}

type RT struct {
	Hdr        RR_Header
	Preference uint16
	Host       string `dns:"cdomain-name"`
}

func (rr *RT) Header() *RR_Header { return &rr.Hdr }
func (rr *RT) copy() RR           { return &RT{*rr.Hdr.copyHeader(), rr.Preference, rr.Host} }

func (rr *RT) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Preference)) + " " + rr.Host
}

func (rr *RT) len() int {
	l := len(rr.Host) + 1
	return rr.Hdr.len() + l + 2
}

type NS struct {
	Hdr RR_Header
	Ns  string `dns:"cdomain-name"`
}

func (rr *NS) Header() *RR_Header { return &rr.Hdr }
func (rr *NS) copy() RR           { return &NS{*rr.Hdr.copyHeader(), rr.Ns} }

func (rr *NS) String() string {
	return rr.Hdr.String() + rr.Ns
}

func (rr *NS) len() int {
	l := len(rr.Ns) + 1
	return rr.Hdr.len() + l
}

type PTR struct {
	Hdr RR_Header
	Ptr string `dns:"cdomain-name"`
}

func (rr *PTR) Header() *RR_Header { return &rr.Hdr }
func (rr *PTR) copy() RR           { return &PTR{*rr.Hdr.copyHeader(), rr.Ptr} }

func (rr *PTR) String() string {
	return rr.Hdr.String() + rr.Ptr
}

func (rr *PTR) len() int {
	l := len(rr.Ptr) + 1
	return rr.Hdr.len() + l
}

type RP struct {
	Hdr  RR_Header
	Mbox string `dns:"domain-name"`
	Txt  string `dns:"domain-name"`
}

func (rr *RP) Header() *RR_Header { return &rr.Hdr }
func (rr *RP) copy() RR           { return &RP{*rr.Hdr.copyHeader(), rr.Mbox, rr.Txt} }

func (rr *RP) String() string {
	return rr.Hdr.String() + rr.Mbox + " " + rr.Txt
}

func (rr *RP) len() int {
	return rr.Hdr.len() + len(rr.Mbox) + 1 + len(rr.Txt) + 1
}

type SOA struct {
	Hdr     RR_Header
	Ns      string `dns:"cdomain-name"`
	Mbox    string `dns:"cdomain-name"`
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minttl  uint32
}

func (rr *SOA) Header() *RR_Header { return &rr.Hdr }
func (rr *SOA) copy() RR {
	return &SOA{*rr.Hdr.copyHeader(), rr.Ns, rr.Mbox, rr.Serial, rr.Refresh, rr.Retry, rr.Expire, rr.Minttl}
}

func (rr *SOA) String() string {
	return rr.Hdr.String() + rr.Ns + " " + rr.Mbox +
		" " + strconv.FormatInt(int64(rr.Serial), 10) +
		" " + strconv.FormatInt(int64(rr.Refresh), 10) +
		" " + strconv.FormatInt(int64(rr.Retry), 10) +
		" " + strconv.FormatInt(int64(rr.Expire), 10) +
		" " + strconv.FormatInt(int64(rr.Minttl), 10)
}

func (rr *SOA) len() int {
	l := len(rr.Ns) + 1
	n := len(rr.Mbox) + 1
	return rr.Hdr.len() + l + n + 20
}

type TXT struct {
	Hdr RR_Header
	Txt []string `dns:"txt"`
}

func (rr *TXT) Header() *RR_Header { return &rr.Hdr }
func (rr *TXT) copy() RR           { return &TXT{*rr.Hdr.copyHeader(), rr.Txt} } // this doesn't really copy Txt does it? TODO(mg)

func (rr *TXT) String() string {
	s := rr.Hdr.String()
	for i, s1 := range rr.Txt {
		if i > 0 {
			s += " " + strconv.QuoteToASCII(s1)
		} else {
			s += strconv.QuoteToASCII(s1)
		}
	}
	return s
}

func (rr *TXT) len() int {
	l := rr.Hdr.len()
	for _, t := range rr.Txt {
		l += len(t) + 1
	}
	return l
}

type SPF struct {
	Hdr RR_Header
	Txt []string `dns:"txt"`
}

func (rr *SPF) Header() *RR_Header { return &rr.Hdr }
func (rr *SPF) copy() RR           { return &SPF{*rr.Hdr.copyHeader(), rr.Txt} }

func (rr *SPF) String() string {
	s := rr.Hdr.String()
	for i, s1 := range rr.Txt {
		if i > 0 {
			s += " " + strconv.QuoteToASCII(s1)
		} else {
			s += strconv.QuoteToASCII(s1)
		}
	}
	return s
}

func (rr *SPF) len() int {
	l := rr.Hdr.len()
	for _, t := range rr.Txt {
		l += len(t)
	}
	return l
}

type SRV struct {
	Hdr      RR_Header
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string `dns:"domain-name"`
}

func (rr *SRV) Header() *RR_Header { return &rr.Hdr }
func (rr *SRV) copy() RR {
	return &SRV{*rr.Hdr.copyHeader(), rr.Priority, rr.Weight, rr.Port, rr.Target}
}

func (rr *SRV) String() string {
	return rr.Hdr.String() +
		strconv.Itoa(int(rr.Priority)) + " " +
		strconv.Itoa(int(rr.Weight)) + " " +
		strconv.Itoa(int(rr.Port)) + " " + rr.Target
}

func (rr *SRV) len() int {
	l := len(rr.Target) + 1
	return rr.Hdr.len() + l + 6
}

type NAPTR struct {
	Hdr         RR_Header
	Order       uint16
	Preference  uint16
	Flags       string
	Service     string
	Regexp      string
	Replacement string `dns:"domain-name"`
}

func (rr *NAPTR) Header() *RR_Header { return &rr.Hdr }
func (rr *NAPTR) copy() RR {
	return &NAPTR{*rr.Hdr.copyHeader(), rr.Order, rr.Preference, rr.Flags, rr.Service, rr.Regexp, rr.Replacement}
}

func (rr *NAPTR) String() string {
	return rr.Hdr.String() +
		strconv.Itoa(int(rr.Order)) + " " +
		strconv.Itoa(int(rr.Preference)) + " " +
		"\"" + rr.Flags + "\" " +
		"\"" + rr.Service + "\" " +
		"\"" + rr.Regexp + "\" " +
		rr.Replacement
}

func (rr *NAPTR) len() int {
	return rr.Hdr.len() + 4 + len(rr.Flags) + len(rr.Service) +
		len(rr.Regexp) + len(rr.Replacement) + 1
}

// See RFC 4398.
type CERT struct {
	Hdr         RR_Header
	Type        uint16
	KeyTag      uint16
	Algorithm   uint8
	Certificate string `dns:"base64"`
}

func (rr *CERT) Header() *RR_Header { return &rr.Hdr }
func (rr *CERT) copy() RR {
	return &CERT{*rr.Hdr.copyHeader(), rr.Type, rr.KeyTag, rr.Algorithm, rr.Certificate}
}

func (rr *CERT) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Type)) +
		" " + strconv.Itoa(int(rr.KeyTag)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + rr.Certificate
}

func (rr *CERT) len() int {
	return rr.Hdr.len() + 5 +
		base64.StdEncoding.DecodedLen(len(rr.Certificate))
}

// See RFC 2672.
type DNAME struct {
	Hdr    RR_Header
	Target string `dns:"domain-name"`
}

func (rr *DNAME) Header() *RR_Header { return &rr.Hdr }
func (rr *DNAME) copy() RR           { return &DNAME{*rr.Hdr.copyHeader(), rr.Target} }

func (rr *DNAME) String() string {
	return rr.Hdr.String() + rr.Target
}

func (rr *DNAME) len() int {
	l := len(rr.Target) + 1
	return rr.Hdr.len() + l
}

type A struct {
	Hdr RR_Header
	A   net.IP `dns:"a"`
}

func (rr *A) Header() *RR_Header { return &rr.Hdr }
func (rr *A) copy() RR           { return &A{*rr.Hdr.copyHeader(), rr.A} }
func (rr *A) len() int           { return rr.Hdr.len() + net.IPv4len }

func (rr *A) String() string {
	if rr.A == nil {
		return rr.Hdr.String()
	}
	return rr.Hdr.String() + rr.A.String()
}

type AAAA struct {
	Hdr  RR_Header
	AAAA net.IP `dns:"aaaa"`
}

func (rr *AAAA) Header() *RR_Header { return &rr.Hdr }
func (rr *AAAA) copy() RR           { return &AAAA{*rr.Hdr.copyHeader(), rr.AAAA} }
func (rr *AAAA) len() int           { return rr.Hdr.len() + net.IPv6len }

func (rr *AAAA) String() string {
	if rr.AAAA == nil {
		return rr.Hdr.String()
	}
	return rr.Hdr.String() + rr.AAAA.String()
}

type LOC struct {
	Hdr       RR_Header
	Version   uint8
	Size      uint8
	HorizPre  uint8
	VertPre   uint8
	Latitude  uint32
	Longitude uint32
	Altitude  uint32
}

func (rr *LOC) Header() *RR_Header { return &rr.Hdr }
func (rr *LOC) copy() RR {
	return &LOC{*rr.Hdr.copyHeader(), rr.Version, rr.Size, rr.HorizPre, rr.VertPre, rr.Latitude, rr.Longitude, rr.Altitude}
}

func (rr *LOC) String() string {
	s := rr.Hdr.String()
	// Copied from ldns
	// Latitude
	lat := rr.Latitude
	north := "N"
	if lat > _LOC_EQUATOR {
		lat = lat - _LOC_EQUATOR
	} else {
		north = "S"
		lat = _LOC_EQUATOR - lat
	}
	h := lat / (1000 * 60 * 60)
	lat = lat % (1000 * 60 * 60)
	m := lat / (1000 * 60)
	lat = lat % (1000 * 60)
	s += fmt.Sprintf("%02d %02d %0.3f %s ", h, m, (float32(lat) / 1000), north)
	// Longitude
	lon := rr.Longitude
	east := "E"
	if lon > _LOC_EQUATOR {
		lon = lon - _LOC_EQUATOR
	} else {
		east = "W"
		lon = _LOC_EQUATOR - lon
	}
	h = lon / (1000 * 60 * 60)
	lon = lon % (1000 * 60 * 60)
	m = lon / (1000 * 60)
	lon = lon % (1000 * 60)
	s += fmt.Sprintf("%02d %02d %0.3f %s ", h, m, (float32(lon) / 1000), east)

	s1 := rr.Altitude / 100.00
	s1 -= 100000
	if rr.Altitude%100 == 0 {
		s += fmt.Sprintf("%.2fm ", float32(s1))
	} else {
		s += fmt.Sprintf("%.0fm ", float32(s1))
	}
	s += cmToString((rr.Size&0xf0)>>4, rr.Size&0x0f) + "m "
	s += cmToString((rr.HorizPre&0xf0)>>4, rr.HorizPre&0x0f) + "m "
	s += cmToString((rr.VertPre&0xf0)>>4, rr.VertPre&0x0f) + "m"
	return s
}

func (rr *LOC) len() int {
	return rr.Hdr.len() + 4 + 12
}

type RRSIG struct {
	Hdr         RR_Header
	TypeCovered uint16
	Algorithm   uint8
	Labels      uint8
	OrigTtl     uint32
	Expiration  uint32
	Inception   uint32
	KeyTag      uint16
	SignerName  string `dns:"domain-name"`
	Signature   string `dns:"base64"`
}

func (rr *RRSIG) Header() *RR_Header { return &rr.Hdr }
func (rr *RRSIG) copy() RR {
	return &RRSIG{*rr.Hdr.copyHeader(), rr.TypeCovered, rr.Algorithm, rr.Labels, rr.OrigTtl, rr.Expiration, rr.Inception, rr.KeyTag, rr.SignerName, rr.Signature}
}

func (rr *RRSIG) String() string {
	s := rr.Hdr.String()
	s += Type(rr.TypeCovered).String()
	s += " " + strconv.Itoa(int(rr.Algorithm)) +
		" " + strconv.Itoa(int(rr.Labels)) +
		" " + strconv.FormatInt(int64(rr.OrigTtl), 10) +
		" " + TimeToString(rr.Expiration) +
		" " + TimeToString(rr.Inception) +
		" " + strconv.Itoa(int(rr.KeyTag)) +
		" " + rr.SignerName +
		" " + rr.Signature
	return s
}

func (rr *RRSIG) len() int {
	return rr.Hdr.len() + len(rr.SignerName) + 1 +
		base64.StdEncoding.DecodedLen(len(rr.Signature)) + 18
}

type NSEC struct {
	Hdr        RR_Header
	NextDomain string   `dns:"domain-name"`
	TypeBitMap []uint16 `dns:"nsec"`
}

func (rr *NSEC) Header() *RR_Header { return &rr.Hdr }
func (rr *NSEC) copy() RR           { return &NSEC{*rr.Hdr.copyHeader(), rr.NextDomain, rr.TypeBitMap} }

func (rr *NSEC) String() string {
	s := rr.Hdr.String() + rr.NextDomain
	for i := 0; i < len(rr.TypeBitMap); i++ {
		s += " " + Type(rr.TypeBitMap[i]).String()
	}
	return s
}

func (rr *NSEC) len() int {
	l := rr.Hdr.len() + len(rr.NextDomain) + 1
	lastwindow := uint32(2 ^ 32 + 1)
	for _, t := range rr.TypeBitMap {
		window := t / 256
		if uint32(window) != lastwindow {
			l += 1 + 32
		}
		lastwindow = uint32(window)
	}
	return l
}

type DS struct {
	Hdr        RR_Header
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string `dns:"hex"`
}

func (rr *DS) Header() *RR_Header { return &rr.Hdr }
func (rr *DS) copy() RR {
	return &DS{*rr.Hdr.copyHeader(), rr.KeyTag, rr.Algorithm, rr.DigestType, rr.Digest}
}

func (rr *DS) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.KeyTag)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + strconv.Itoa(int(rr.DigestType)) +
		" " + strings.ToUpper(rr.Digest)
}

func (rr *DS) len() int {
	return rr.Hdr.len() + 4 + len(rr.Digest)/2
}

type CDS struct {
	Hdr        RR_Header
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string `dns:"hex"`
}

func (rr *CDS) Header() *RR_Header { return &rr.Hdr }
func (rr *CDS) copy() RR {
	return &CDS{*rr.Hdr.copyHeader(), rr.KeyTag, rr.Algorithm, rr.DigestType, rr.Digest}
}

func (rr *CDS) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.KeyTag)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + strconv.Itoa(int(rr.DigestType)) +
		" " + strings.ToUpper(rr.Digest)
}

func (rr *CDS) len() int {
	return rr.Hdr.len() + 4 + len(rr.Digest)/2
}

type DLV struct {
	Hdr        RR_Header
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string `dns:"hex"`
}

func (rr *DLV) Header() *RR_Header { return &rr.Hdr }
func (rr *DLV) copy() RR {
	return &DLV{*rr.Hdr.copyHeader(), rr.KeyTag, rr.Algorithm, rr.DigestType, rr.Digest}
}

func (rr *DLV) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.KeyTag)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + strconv.Itoa(int(rr.DigestType)) +
		" " + strings.ToUpper(rr.Digest)
}

func (rr *DLV) len() int {
	return rr.Hdr.len() + 4 + len(rr.Digest)/2
}

type KX struct {
	Hdr        RR_Header
	Preference uint16
	Exchanger  string `dns:"domain-name"`
}

func (rr *KX) Header() *RR_Header { return &rr.Hdr }
func (rr *KX) copy() RR           { return &KX{*rr.Hdr.copyHeader(), rr.Preference, rr.Exchanger} }

func (rr *KX) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Preference)) +
		" " + rr.Exchanger
}

func (rr *KX) len() int {
	return rr.Hdr.len() + 2 + len(rr.Exchanger)
}

type TA struct {
	Hdr        RR_Header
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string `dns:"hex"`
}

func (rr *TA) Header() *RR_Header { return &rr.Hdr }
func (rr *TA) copy() RR {
	return &TA{*rr.Hdr.copyHeader(), rr.KeyTag, rr.Algorithm, rr.DigestType, rr.Digest}
}

func (rr *TA) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.KeyTag)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + strconv.Itoa(int(rr.DigestType)) +
		" " + strings.ToUpper(rr.Digest)
}

func (rr *TA) len() int {
	return rr.Hdr.len() + 4 + len(rr.Digest)/2
}

type TALINK struct {
	Hdr          RR_Header
	PreviousName string `dns:"domain-name"`
	NextName     string `dns:"domain-name"`
}

func (rr *TALINK) Header() *RR_Header { return &rr.Hdr }
func (rr *TALINK) copy() RR           { return &TALINK{*rr.Hdr.copyHeader(), rr.PreviousName, rr.NextName} }

func (rr *TALINK) String() string {
	return rr.Hdr.String() +
		" " + rr.PreviousName + " " + rr.NextName
}

func (rr *TALINK) len() int {
	return rr.Hdr.len() + len(rr.PreviousName) + len(rr.NextName) + 2
}

type SSHFP struct {
	Hdr         RR_Header
	Algorithm   uint8
	Type        uint8
	FingerPrint string `dns:"hex"`
}

func (rr *SSHFP) Header() *RR_Header { return &rr.Hdr }
func (rr *SSHFP) copy() RR {
	return &SSHFP{*rr.Hdr.copyHeader(), rr.Algorithm, rr.Type, rr.FingerPrint}
}

func (rr *SSHFP) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Algorithm)) +
		" " + strconv.Itoa(int(rr.Type)) +
		" " + strings.ToUpper(rr.FingerPrint)
}

func (rr *SSHFP) len() int {
	return rr.Hdr.len() + 2 + len(rr.FingerPrint)/2
}

type IPSECKEY struct {
	Hdr         RR_Header
	Precedence  uint8
	GatewayType uint8
	Algorithm   uint8
	Gateway     string `dns:"ipseckey"`
	PublicKey   string `dns:"base64"`
}

func (rr *IPSECKEY) Header() *RR_Header { return &rr.Hdr }
func (rr *IPSECKEY) copy() RR {
	return &IPSECKEY{*rr.Hdr.copyHeader(), rr.Precedence, rr.GatewayType, rr.Algorithm, rr.Gateway, rr.PublicKey}
}

func (rr *IPSECKEY) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Precedence)) +
		" " + strconv.Itoa(int(rr.GatewayType)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + rr.Gateway +
		" " + rr.PublicKey
}

func (rr *IPSECKEY) len() int {
	return rr.Hdr.len() + 3 + len(rr.Gateway) + 1 +
		base64.StdEncoding.DecodedLen(len(rr.PublicKey))
}

type DNSKEY struct {
	Hdr       RR_Header
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey string `dns:"base64"`
}

func (rr *DNSKEY) Header() *RR_Header { return &rr.Hdr }
func (rr *DNSKEY) copy() RR {
	return &DNSKEY{*rr.Hdr.copyHeader(), rr.Flags, rr.Protocol, rr.Algorithm, rr.PublicKey}
}

func (rr *DNSKEY) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Flags)) +
		" " + strconv.Itoa(int(rr.Protocol)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + rr.PublicKey
}

func (rr *DNSKEY) len() int {
	return rr.Hdr.len() + 4 +
		base64.StdEncoding.DecodedLen(len(rr.PublicKey))
}

type RKEY struct {
	Hdr       RR_Header
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey string `dns:"base64"`
}

func (rr *RKEY) Header() *RR_Header { return &rr.Hdr }
func (rr *RKEY) copy() RR {
	return &RKEY{*rr.Hdr.copyHeader(), rr.Flags, rr.Protocol, rr.Algorithm, rr.PublicKey}
}

func (rr *RKEY) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Flags)) +
		" " + strconv.Itoa(int(rr.Protocol)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + rr.PublicKey
}

func (rr *RKEY) len() int {
	return rr.Hdr.len() + 4 +
		base64.StdEncoding.DecodedLen(len(rr.PublicKey))
}

type NSEC3 struct {
	Hdr        RR_Header
	Hash       uint8
	Flags      uint8
	Iterations uint16
	SaltLength uint8
	Salt       string `dns:"size-hex"`
	HashLength uint8
	NextDomain string   `dns:"size-base32"`
	TypeBitMap []uint16 `dns:"nsec"`
}

func (rr *NSEC3) Header() *RR_Header { return &rr.Hdr }
func (rr *NSEC3) copy() RR {
	return &NSEC3{*rr.Hdr.copyHeader(), rr.Hash, rr.Flags, rr.Iterations, rr.SaltLength, rr.Salt, rr.HashLength, rr.NextDomain, rr.TypeBitMap}
}

func (rr *NSEC3) String() string {
	s := rr.Hdr.String()
	s += strconv.Itoa(int(rr.Hash)) +
		" " + strconv.Itoa(int(rr.Flags)) +
		" " + strconv.Itoa(int(rr.Iterations)) +
		" " + saltToString(rr.Salt) +
		" " + rr.NextDomain
	for i := 0; i < len(rr.TypeBitMap); i++ {
		s += " " + Type(rr.TypeBitMap[i]).String()
	}
	return s
}

func (rr *NSEC3) len() int {
	l := rr.Hdr.len() + 6 + len(rr.Salt)/2 + 1 + len(rr.NextDomain) + 1
	lastwindow := uint32(2 ^ 32 + 1)
	for _, t := range rr.TypeBitMap {
		window := t / 256
		if uint32(window) != lastwindow {
			l += 1 + 32
		}
		lastwindow = uint32(window)
	}
	return l
}

type NSEC3PARAM struct {
	Hdr        RR_Header
	Hash       uint8
	Flags      uint8
	Iterations uint16
	SaltLength uint8
	Salt       string `dns:"hex"`
}

func (rr *NSEC3PARAM) Header() *RR_Header { return &rr.Hdr }
func (rr *NSEC3PARAM) copy() RR {
	return &NSEC3PARAM{*rr.Hdr.copyHeader(), rr.Hash, rr.Flags, rr.Iterations, rr.SaltLength, rr.Salt}
}

func (rr *NSEC3PARAM) String() string {
	s := rr.Hdr.String()
	s += strconv.Itoa(int(rr.Hash)) +
		" " + strconv.Itoa(int(rr.Flags)) +
		" " + strconv.Itoa(int(rr.Iterations)) +
		" " + saltToString(rr.Salt)
	return s
}

func (rr *NSEC3PARAM) len() int {
	return rr.Hdr.len() + 2 + 4 + 1 + len(rr.Salt)/2
}

type TKEY struct {
	Hdr        RR_Header
	Algorithm  string `dns:"domain-name"`
	Inception  uint32
	Expiration uint32
	Mode       uint16
	Error      uint16
	KeySize    uint16
	Key        string
	OtherLen   uint16
	OtherData  string
}

func (rr *TKEY) Header() *RR_Header { return &rr.Hdr }
func (rr *TKEY) copy() RR {
	return &TKEY{*rr.Hdr.copyHeader(), rr.Algorithm, rr.Inception, rr.Expiration, rr.Mode, rr.Error, rr.KeySize, rr.Key, rr.OtherLen, rr.OtherData}
}

func (rr *TKEY) String() string {
	// It has no presentation format
	return ""
}

func (rr *TKEY) len() int {
	return rr.Hdr.len() + len(rr.Algorithm) + 1 + 4 + 4 + 6 +
		len(rr.Key) + 2 + len(rr.OtherData)
}

// RFC3597 representes an unknown RR.
type RFC3597 struct {
	Hdr   RR_Header
	Rdata string `dns:"hex"`
}

func (rr *RFC3597) Header() *RR_Header { return &rr.Hdr }
func (rr *RFC3597) copy() RR           { return &RFC3597{*rr.Hdr.copyHeader(), rr.Rdata} }

func (rr *RFC3597) String() string {
	s := rr.Hdr.String()
	s += "\\# " + strconv.Itoa(len(rr.Rdata)/2) + " " + rr.Rdata
	return s
}

func (rr *RFC3597) len() int {
	return rr.Hdr.len() + len(rr.Rdata)/2
}

type URI struct {
	Hdr      RR_Header
	Priority uint16
	Weight   uint16
	Target   []string `dns:"txt"`
}

func (rr *URI) Header() *RR_Header { return &rr.Hdr }
func (rr *URI) copy() RR           { return &URI{*rr.Hdr.copyHeader(), rr.Weight, rr.Priority, rr.Target} }

func (rr *URI) String() string {
	s := rr.Hdr.String() + strconv.Itoa(int(rr.Priority)) +
		" " + strconv.Itoa(int(rr.Weight))
	for i, s1 := range rr.Target {
		if i > 0 {
			s += " " + strconv.QuoteToASCII(s1)
		} else {
			s += strconv.QuoteToASCII(s1)
		}
	}
	return s
}

func (rr *URI) len() int {
	return rr.Hdr.len() + 4 + len(rr.Target) + 1
}

type DHCID struct {
	Hdr    RR_Header
	Digest string `dns:"base64"`
}

func (rr *DHCID) Header() *RR_Header { return &rr.Hdr }
func (rr *DHCID) copy() RR           { return &DHCID{*rr.Hdr.copyHeader(), rr.Digest} }

func (rr *DHCID) String() string {
	return rr.Hdr.String() + rr.Digest
}

func (rr *DHCID) len() int {
	return rr.Hdr.len() +
		base64.StdEncoding.DecodedLen(len(rr.Digest))
}

type TLSA struct {
	Hdr          RR_Header
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	Certificate  string `dns:"hex"`
}

func (rr *TLSA) Header() *RR_Header { return &rr.Hdr }
func (rr *TLSA) copy() RR {
	return &TLSA{*rr.Hdr.copyHeader(), rr.Usage, rr.Selector, rr.MatchingType, rr.Certificate}
}

func (rr *TLSA) String() string {
	return rr.Hdr.String() +
		" " + strconv.Itoa(int(rr.Usage)) +
		" " + strconv.Itoa(int(rr.Selector)) +
		" " + strconv.Itoa(int(rr.MatchingType)) +
		" " + rr.Certificate
}

func (rr *TLSA) len() int {
	return rr.Hdr.len() + 3 + len(rr.Certificate)/2
}

type HIP struct {
	Hdr                RR_Header
	HitLength          uint8
	PublicKeyAlgorithm uint8
	PublicKeyLength    uint16
	Hit                string   `dns:"hex"`
	PublicKey          string   `dns:"base64"`
	RendezvousServers  []string `dns:"domain-name"`
}

func (rr *HIP) Header() *RR_Header { return &rr.Hdr }
func (rr *HIP) copy() RR {
	return &HIP{*rr.Hdr.copyHeader(), rr.HitLength, rr.PublicKeyAlgorithm, rr.PublicKeyLength, rr.Hit, rr.PublicKey, rr.RendezvousServers}
}

func (rr *HIP) String() string {
	s := rr.Hdr.String() +
		" " + strconv.Itoa(int(rr.PublicKeyAlgorithm)) +
		" " + rr.Hit +
		" " + rr.PublicKey
	for _, d := range rr.RendezvousServers {
		s += " " + d
	}
	return s
}

func (rr *HIP) len() int {
	l := rr.Hdr.len() + 4 +
		len(rr.Hit)/2 +
		base64.StdEncoding.DecodedLen(len(rr.PublicKey))
	for _, d := range rr.RendezvousServers {
		l += len(d) + 1
	}
	return l
}

type NINFO struct {
	Hdr    RR_Header
	ZSData []string `dns:"txt"`
}

func (rr *NINFO) Header() *RR_Header { return &rr.Hdr }
func (rr *NINFO) copy() RR           { return &NINFO{*rr.Hdr.copyHeader(), rr.ZSData} }

func (rr *NINFO) String() string {
	s := rr.Hdr.String()
	for i, s1 := range rr.ZSData {
		if i > 0 {
			s += " " + strconv.QuoteToASCII(s1)
		} else {
			s += strconv.QuoteToASCII(s1)
		}
	}
	return s
}

func (rr *NINFO) len() int {
	l := rr.Hdr.len()
	for _, t := range rr.ZSData {
		l += len(t)
	}
	return l
}

type WKS struct {
	Hdr      RR_Header
	Address  net.IP `dns:"a"`
	Protocol uint8
	BitMap   []uint16 `dns:"wks"`
}

func (rr *WKS) Header() *RR_Header { return &rr.Hdr }
func (rr *WKS) copy() RR           { return &WKS{*rr.Hdr.copyHeader(), rr.Address, rr.Protocol, rr.BitMap} }

func (rr *WKS) String() (s string) {
	s = rr.Hdr.String()
	if rr.Address != nil {
		s += rr.Address.String()
	}
	for i := 0; i < len(rr.BitMap); i++ {
		// should lookup the port
		s += " " + strconv.Itoa(int(rr.BitMap[i]))
	}
	return s
}

func (rr *WKS) len() int {
	return rr.Hdr.len() + net.IPv4len + 1
}

type NID struct {
	Hdr        RR_Header
	Preference uint16
	NodeID     uint64
}

func (rr *NID) Header() *RR_Header { return &rr.Hdr }
func (rr *NID) copy() RR           { return &NID{*rr.Hdr.copyHeader(), rr.Preference, rr.NodeID} }

func (rr *NID) String() string {
	s := rr.Hdr.String() + strconv.Itoa(int(rr.Preference))
	node := fmt.Sprintf("%0.16x", rr.NodeID)
	s += " " + node[0:4] + ":" + node[4:8] + ":" + node[8:12] + ":" + node[12:16]
	return s
}

func (rr *NID) len() int {
	return rr.Hdr.len() + 2 + 8
}

type L32 struct {
	Hdr        RR_Header
	Preference uint16
	Locator32  net.IP `dns:"a"`
}

func (rr *L32) Header() *RR_Header { return &rr.Hdr }
func (rr *L32) copy() RR           { return &L32{*rr.Hdr.copyHeader(), rr.Preference, rr.Locator32} }

func (rr *L32) String() string {
	if rr.Locator32 == nil {
		return rr.Hdr.String() + strconv.Itoa(int(rr.Preference))
	}
	return rr.Hdr.String() + strconv.Itoa(int(rr.Preference)) +
		" " + rr.Locator32.String()
}

func (rr *L32) len() int {
	return rr.Hdr.len() + net.IPv4len
}

type L64 struct {
	Hdr        RR_Header
	Preference uint16
	Locator64  uint64
}

func (rr *L64) Header() *RR_Header { return &rr.Hdr }
func (rr *L64) copy() RR           { return &L64{*rr.Hdr.copyHeader(), rr.Preference, rr.Locator64} }

func (rr *L64) String() string {
	s := rr.Hdr.String() + strconv.Itoa(int(rr.Preference))
	node := fmt.Sprintf("%0.16X", rr.Locator64)
	s += " " + node[0:4] + ":" + node[4:8] + ":" + node[8:12] + ":" + node[12:16]
	return s
}

func (rr *L64) len() int {
	return rr.Hdr.len() + 2 + 8
}

type LP struct {
	Hdr        RR_Header
	Preference uint16
	Fqdn       string `dns:"domain-name"`
}

func (rr *LP) Header() *RR_Header { return &rr.Hdr }
func (rr *LP) copy() RR           { return &LP{*rr.Hdr.copyHeader(), rr.Preference, rr.Fqdn} }
func (rr *LP) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Preference)) + " " + rr.Fqdn
}
func (rr *LP) len() int { return rr.Hdr.len() + 2 + len(rr.Fqdn) + 1 }

type EUI48 struct {
	Hdr     RR_Header
	Address uint64 `dns:"uint48"`
}

func (rr *EUI48) Header() *RR_Header { return &rr.Hdr }
func (rr *EUI48) copy() RR           { return &EUI48{*rr.Hdr.copyHeader(), rr.Address} }
func (rr *EUI48) String() string     { return rr.Hdr.String() + euiToString(rr.Address, 48) }
func (rr *EUI48) len() int           { return rr.Hdr.len() + 6 }

type EUI64 struct {
	Hdr     RR_Header
	Address uint64
}

func (rr *EUI64) Header() *RR_Header { return &rr.Hdr }
func (rr *EUI64) copy() RR           { return &EUI64{*rr.Hdr.copyHeader(), rr.Address} }
func (rr *EUI64) String() string     { return rr.Hdr.String() + euiToString(rr.Address, 64) }
func (rr *EUI64) len() int           { return rr.Hdr.len() + 8 }

type CAA struct {
	Hdr   RR_Header
	Flag  uint8
	Tag   string
	Value []string `dns:"txt"`
}

func (rr *CAA) Header() *RR_Header { return &rr.Hdr }
func (rr *CAA) copy() RR           { return &CAA{*rr.Hdr.copyHeader(), rr.Flag, rr.Tag, rr.Value} }

func (rr *CAA) String() string {
	s := rr.Hdr.String() + strconv.FormatInt(int64(rr.Flag), 10) + " " + rr.Tag
	for i, s1 := range rr.Value {
		if i > 0 {
			s += " " + strconv.QuoteToASCII(s1)
		} else {
			s += strconv.QuoteToASCII(s1)
		}
	}
	return s
}

func (rr *CAA) len() int {
	l := rr.Hdr.len() + 1 + len(rr.Tag)
	for _, t := range rr.Value {
		l += len(t)
	}
	return l
}

type UID struct {
	Hdr RR_Header
	Uid uint32
}

func (rr *UID) Header() *RR_Header { return &rr.Hdr }
func (rr *UID) copy() RR           { return &UID{*rr.Hdr.copyHeader(), rr.Uid} }
func (rr *UID) String() string     { return rr.Hdr.String() + strconv.FormatInt(int64(rr.Uid), 10) }
func (rr *UID) len() int           { return rr.Hdr.len() + 4 }

type GID struct {
	Hdr RR_Header
	Gid uint32
}

func (rr *GID) Header() *RR_Header { return &rr.Hdr }
func (rr *GID) copy() RR           { return &GID{*rr.Hdr.copyHeader(), rr.Gid} }
func (rr *GID) String() string     { return rr.Hdr.String() + strconv.FormatInt(int64(rr.Gid), 10) }
func (rr *GID) len() int           { return rr.Hdr.len() + 4 }

type UINFO struct {
	Hdr   RR_Header
	Uinfo string
}

func (rr *UINFO) Header() *RR_Header { return &rr.Hdr }
func (rr *UINFO) copy() RR           { return &UINFO{*rr.Hdr.copyHeader(), rr.Uinfo} }
func (rr *UINFO) String() string     { return rr.Hdr.String() + strconv.QuoteToASCII(rr.Uinfo) }
func (rr *UINFO) len() int           { return rr.Hdr.len() + len(rr.Uinfo) + 1 }

// TimeToString translates the RRSIG's incep. and expir. times to the
// string representation used when printing the record.
// It takes serial arithmetic (RFC 1982) into account.
func TimeToString(t uint32) string {
	mod := ((int64(t) - time.Now().Unix()) / year68) - 1
	if mod < 0 {
		mod = 0
	}
	ti := time.Unix(int64(t)-(mod*year68), 0).UTC()
	return ti.Format("20060102150405")
}

// StringToTime translates the RRSIG's incep. and expir. times from
// string values like "20110403154150" to an 32 bit integer.
// It takes serial arithmetic (RFC 1982) into account.
func StringToTime(s string) (uint32, error) {
	t, e := time.Parse("20060102150405", s)
	if e != nil {
		return 0, e
	}
	mod := (t.Unix() / year68) - 1
	if mod < 0 {
		mod = 0
	}
	return uint32(t.Unix() - (mod * year68)), nil
}

// saltToString converts a NSECX salt to uppercase and
// returns "-" when it is empty
func saltToString(s string) string {
	if len(s) == 0 {
		return "-"
	}
	return strings.ToUpper(s)
}

func cmToString(mantissa, exponent uint8) string {
	switch exponent {
	case 0, 1:
		if exponent == 1 {
			mantissa *= 10
		}
		return fmt.Sprintf("%.02f", float32(mantissa))
	default:
		s := fmt.Sprintf("%d", mantissa)
		for i := uint8(0); i < exponent-2; i++ {
			s += "0"
		}
		return s
	}
	panic("dns: not reached")
}

func euiToString(eui uint64, bits int) (hex string) {
	switch bits {
	case 64:
		hex = fmt.Sprintf("%16.16x", eui)
		hex = hex[0:2] + "-" + hex[2:4] + "-" + hex[4:6] + "-" + hex[6:8] +
			"-" + hex[8:10] + "-" + hex[10:12] + "-" + hex[12:14] + "-" + hex[14:16]
	case 48:
		hex = fmt.Sprintf("%12.12x", eui)
		hex = hex[0:2] + "-" + hex[2:4] + "-" + hex[4:6] + "-" + hex[6:8] +
			"-" + hex[8:10] + "-" + hex[10:12]
	}
	return
}

// Map of constructors for each RR wire type.
var rr_mk = map[uint16]func() RR{
	TypeCNAME:      func() RR { return new(CNAME) },
	TypeHINFO:      func() RR { return new(HINFO) },
	TypeMB:         func() RR { return new(MB) },
	TypeMG:         func() RR { return new(MG) },
	TypeMD:         func() RR { return new(MD) },
	TypeMF:         func() RR { return new(MF) },
	TypeMINFO:      func() RR { return new(MINFO) },
	TypeRP:         func() RR { return new(RP) },
	TypeAFSDB:      func() RR { return new(AFSDB) },
	TypeX25:        func() RR { return new(X25) },
	TypeMR:         func() RR { return new(MR) },
	TypeMX:         func() RR { return new(MX) },
	TypeRKEY:       func() RR { return new(RKEY) },
	TypeNINFO:      func() RR { return new(NINFO) },
	TypeNS:         func() RR { return new(NS) },
	TypePTR:        func() RR { return new(PTR) },
	TypeSOA:        func() RR { return new(SOA) },
	TypeRT:         func() RR { return new(RT) },
	TypeTXT:        func() RR { return new(TXT) },
	TypeSRV:        func() RR { return new(SRV) },
	TypeNAPTR:      func() RR { return new(NAPTR) },
	TypeDNAME:      func() RR { return new(DNAME) },
	TypeA:          func() RR { return new(A) },
	TypeWKS:        func() RR { return new(WKS) },
	TypeAAAA:       func() RR { return new(AAAA) },
	TypeLOC:        func() RR { return new(LOC) },
	TypeOPT:        func() RR { return new(OPT) },
	TypeDS:         func() RR { return new(DS) },
	TypeCDS:        func() RR { return new(CDS) },
	TypeCERT:       func() RR { return new(CERT) },
	TypeKX:         func() RR { return new(KX) },
	TypeSPF:        func() RR { return new(SPF) },
	TypeTALINK:     func() RR { return new(TALINK) },
	TypeSSHFP:      func() RR { return new(SSHFP) },
	TypeRRSIG:      func() RR { return new(RRSIG) },
	TypeNSEC:       func() RR { return new(NSEC) },
	TypeDNSKEY:     func() RR { return new(DNSKEY) },
	TypeNSEC3:      func() RR { return new(NSEC3) },
	TypeDHCID:      func() RR { return new(DHCID) },
	TypeNSEC3PARAM: func() RR { return new(NSEC3PARAM) },
	TypeTKEY:       func() RR { return new(TKEY) },
	TypeTSIG:       func() RR { return new(TSIG) },
	TypeURI:        func() RR { return new(URI) },
	TypeTA:         func() RR { return new(TA) },
	TypeDLV:        func() RR { return new(DLV) },
	TypeTLSA:       func() RR { return new(TLSA) },
	TypeHIP:        func() RR { return new(HIP) },
	TypeNID:        func() RR { return new(NID) },
	TypeL32:        func() RR { return new(L32) },
	TypeL64:        func() RR { return new(L64) },
	TypeLP:         func() RR { return new(LP) },
	TypeEUI48:      func() RR { return new(EUI48) },
	TypeEUI64:      func() RR { return new(EUI64) },
	TypeCAA:        func() RR { return new(CAA) },
	TypeUID:        func() RR { return new(UID) },
	TypeGID:        func() RR { return new(GID) },
	TypeUINFO:      func() RR { return new(UINFO) },
}
