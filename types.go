// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Extended and bugfixes by Miek Gieben

package dns

import (
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Packet formats

// Wire constants and supported types.
const (
	// valid RR_Header.Rrtype and Question.qtype
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
	TypeRT         uint16 = 21
	TypeSIG        uint16 = 24
	TypeKEY        uint16 = 25
	TypeAAAA       uint16 = 28
	TypeLOC        uint16 = 29
	TypeNXT        uint16 = 30
	TypeSRV        uint16 = 33
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
	TypeTALINK     uint16 = 58
	TypeSPF        uint16 = 99

	TypeTKEY uint16 = 249
	TypeTSIG uint16 = 250
	// valid Question.Qtype only
	TypeIXFR  uint16 = 251
	TypeAXFR  uint16 = 252
	TypeMAILB uint16 = 253
	TypeMAILA uint16 = 254
	TypeANY   uint16 = 255

	TypeURI uint16 = 256
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
	if _, ok := Class_str[q.Qclass]; ok {
		s += Class_str[q.Qclass] + "\t"
	} else {
		s += "CLASS" + strconv.Itoa(int(q.Qtype))
	}

	if _, ok := Rr_str[q.Qtype]; ok {
		s += " " + Rr_str[q.Qtype]
	} else {
		s += " " + "TYPE" + strconv.Itoa(int(q.Qtype))
	}
	return s
}

func (q *Question) Len() int {
	l := len(q.Name) + 1
	return l + 4
}

type RR_ANY struct {
	Hdr RR_Header
	// Does not have any rdata
}

func (rr *RR_ANY) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_ANY) String() string {
	return rr.Hdr.String()
}

func (rr *RR_ANY) Len() int {
	return rr.Hdr.Len()
}

func (rr *RR_ANY) Copy() RR {
	return &RR_ANY{*rr.Hdr.CopyHeader()}
}

type RR_CNAME struct {
	Hdr    RR_Header
	Target string `dns:"cdomain-name"`
}

func (rr *RR_CNAME) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_CNAME) String() string {
	return rr.Hdr.String() + rr.Target
}

func (rr *RR_CNAME) Len() int {
	l := len(rr.Target) + 1
	return rr.Hdr.Len() + l
}

func (rr *RR_CNAME) Copy() RR {
	return &RR_CNAME{*rr.Hdr.CopyHeader(), rr.Target}
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

func (rr *RR_HINFO) Len() int {
	return rr.Hdr.Len() + len(rr.Cpu) + len(rr.Os)
}

func (rr *RR_HINFO) Copy() RR {
	return &RR_HINFO{*rr.Hdr.CopyHeader(), rr.Cpu, rr.Os}
}

type RR_MB struct {
	Hdr RR_Header
	Mb  string `dns:"cdomain-name"`
}

func (rr *RR_MB) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_MB) String() string {
	return rr.Hdr.String() + rr.Mb
}

func (rr *RR_MB) Len() int {
	l := len(rr.Mb) + 1
	return rr.Hdr.Len() + l
}

func (rr *RR_MB) Copy() RR {
	return &RR_MB{*rr.Hdr.CopyHeader(), rr.Mb}
}

type RR_MG struct {
	Hdr RR_Header
	Mg  string `dns:"cdomain-name"`
}

func (rr *RR_MG) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_MG) String() string {
	return rr.Hdr.String() + rr.Mg
}

func (rr *RR_MG) Len() int {
	l := len(rr.Mg) + 1
	return rr.Hdr.Len() + l
}

func (rr *RR_MG) Copy() RR {
	return &RR_MG{*rr.Hdr.CopyHeader(), rr.Mg}
}

type RR_MINFO struct {
	Hdr   RR_Header
	Rmail string `dns:"cdomain-name"`
	Email string `dns:"cdomain-name"`
}

func (rr *RR_MINFO) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_MINFO) String() string {
	return rr.Hdr.String() + rr.Rmail + " " + rr.Email
}

func (rr *RR_MINFO) Len() int {
	l := len(rr.Rmail) + 1
	n := len(rr.Email) + 1
	return rr.Hdr.Len() + l + n
}

func (rr *RR_MINFO) Copy() RR {
	return &RR_MINFO{*rr.Hdr.CopyHeader(), rr.Rmail, rr.Email}
}

type RR_MR struct {
	Hdr RR_Header
	Mr  string `dns:"cdomain-name"`
}

func (rr *RR_MR) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_MR) String() string {
	return rr.Hdr.String() + rr.Mr
}

func (rr *RR_MR) Len() int {
	l := len(rr.Mr) + 1
	return rr.Hdr.Len() + l
}

func (rr *RR_MR) Copy() RR {
	return &RR_MR{*rr.Hdr.CopyHeader(), rr.Mr}
}

type RR_MF struct {
	Hdr RR_Header
	Mf  string `dns:"cdomain-name"`
}

func (rr *RR_MF) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_MF) String() string {
	return rr.Hdr.String() + " " + rr.Mf
}

func (rr *RR_MF) Len() int {
	return rr.Hdr.Len() + len(rr.Mf) + 1
}

func (rr *RR_MF) Copy() RR {
	return &RR_MF{*rr.Hdr.CopyHeader(), rr.Mf}
}

type RR_MD struct {
	Hdr RR_Header
	Md  string `dns:"cdomain-name"`
}

func (rr *RR_MD) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_MD) String() string {
	return rr.Hdr.String() + " " + rr.Md
}

func (rr *RR_MD) Len() int {
	return rr.Hdr.Len() + len(rr.Md) + 1
}

func (rr *RR_MD) Copy() RR {
	return &RR_MD{*rr.Hdr.CopyHeader(), rr.Md}
}

type RR_MX struct {
	Hdr  RR_Header
	Pref uint16
	Mx   string `dns:"cdomain-name"`
}

func (rr *RR_MX) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_MX) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Pref)) + " " + rr.Mx
}

func (rr *RR_MX) Len() int {
	l := len(rr.Mx) + 1
	return rr.Hdr.Len() + l + 2
}

func (rr *RR_MX) Copy() RR {
	return &RR_MX{*rr.Hdr.CopyHeader(), rr.Pref, rr.Mx}
}

type RR_AFSDB struct {
	Hdr      RR_Header
	Subtype  uint16
	Hostname string `dns:"cdomain-name"`
}

func (rr *RR_AFSDB) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_AFSDB) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Subtype)) + " " + rr.Hostname
}

func (rr *RR_AFSDB) Len() int {
	l := len(rr.Hostname) + 1
	return rr.Hdr.Len() + l + 2
}

func (rr *RR_AFSDB) Copy() RR {
	return &RR_AFSDB{*rr.Hdr.CopyHeader(), rr.Subtype, rr.Hostname}
}

type RR_RT struct {
	Hdr        RR_Header
	Preference uint16
	Host       string `dns:"cdomain-name"`
}

func (rr *RR_RT) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_RT) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Preference)) + " " + rr.Host
}

func (rr *RR_RT) Len() int {
	l := len(rr.Host) + 1
	return rr.Hdr.Len() + l + 2
}

func (rr *RR_RT) Copy() RR {
	return &RR_RT{*rr.Hdr.CopyHeader(), rr.Preference, rr.Host}
}

type RR_NS struct {
	Hdr RR_Header
	Ns  string `dns:"cdomain-name"`
}

func (rr *RR_NS) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_NS) String() string {
	return rr.Hdr.String() + rr.Ns
}

func (rr *RR_NS) Len() int {
	l := len(rr.Ns) + 1
	return rr.Hdr.Len() + l
}

func (rr *RR_NS) Copy() RR {
	return &RR_NS{*rr.Hdr.CopyHeader(), rr.Ns}
}

type RR_PTR struct {
	Hdr RR_Header
	Ptr string `dns:"cdomain-name"`
}

func (rr *RR_PTR) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_PTR) String() string {
	return rr.Hdr.String() + rr.Ptr
}

func (rr *RR_PTR) Len() int {
	l := len(rr.Ptr) + 1
	return rr.Hdr.Len() + l
}

func (rr *RR_PTR) Copy() RR {
	return &RR_PTR{*rr.Hdr.CopyHeader(), rr.Ptr}
}

type RR_RP struct {
	Hdr  RR_Header
	Mbox string `dns:"domain-name"`
	Txt  string `dns:"domain-name"`
}

func (rr *RR_RP) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_RP) String() string {
	return rr.Hdr.String() + rr.Mbox + " " + rr.Txt
}

func (rr *RR_RP) Len() int {
	return rr.Hdr.Len() + len(rr.Mbox) + 1 + len(rr.Txt) + 1
}

func (rr *RR_RP) Copy() RR {
	return &RR_RP{*rr.Hdr.CopyHeader(), rr.Mbox, rr.Txt}
}

type RR_SOA struct {
	Hdr     RR_Header
	Ns      string `dns:"cdomain-name"`
	Mbox    string `dns:"cdomain-name"`
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
		" " + strconv.FormatInt(int64(rr.Serial), 10) +
		" " + strconv.FormatInt(int64(rr.Refresh), 10) +
		" " + strconv.FormatInt(int64(rr.Retry), 10) +
		" " + strconv.FormatInt(int64(rr.Expire), 10) +
		" " + strconv.FormatInt(int64(rr.Minttl), 10)
}

func (rr *RR_SOA) Len() int {
	l := len(rr.Ns) + 1
	n := len(rr.Mbox) + 1
	return rr.Hdr.Len() + l + n + 20
}

func (rr *RR_SOA) Copy() RR {
	return &RR_SOA{*rr.Hdr.CopyHeader(), rr.Ns, rr.Mbox, rr.Serial, rr.Refresh, rr.Retry, rr.Expire, rr.Minttl}
}

type RR_TXT struct {
	Hdr RR_Header
	Txt []string `dns:"txt"`
}

func (rr *RR_TXT) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_TXT) String() string {
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

func (rr *RR_TXT) Len() int {
	l := rr.Hdr.Len()
	for _, t := range rr.Txt {
		l += len(t)
	}
	return l
}

func (rr *RR_TXT) Copy() RR {
	return &RR_TXT{*rr.Hdr.CopyHeader(), rr.Txt}
}

type RR_SPF struct {
	Hdr RR_Header
	Txt []string `dns:"txt"`
}

func (rr *RR_SPF) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_SPF) String() string {
	s := rr.Hdr.String()
	for i, s1 := range rr.Txt {
		if i > 0 {
			s += " " + "\"" + s1 + "\""
		} else {
			s += "\"" + s1 + "\""
		}
	}
	return s
}

func (rr *RR_SPF) Len() int {
	l := rr.Hdr.Len()
	for _, t := range rr.Txt {
		l += len(t)
	}
	return l
}

func (rr *RR_SPF) Copy() RR {
	return &RR_SPF{*rr.Hdr.CopyHeader(), rr.Txt}
}

type RR_SRV struct {
	Hdr      RR_Header
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string `dns:"domain-name"`
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

func (rr *RR_SRV) Len() int {
	l := len(rr.Target) + 1
	return rr.Hdr.Len() + l + 6
}

func (rr *RR_SRV) Copy() RR {
	return &RR_SRV{*rr.Hdr.CopyHeader(), rr.Priority, rr.Weight, rr.Port, rr.Target}
}

type RR_NAPTR struct {
	Hdr         RR_Header
	Order       uint16
	Pref        uint16
	Flags       string
	Service     string
	Regexp      string
	Replacement string `dns:"domain-name"`
}

func (rr *RR_NAPTR) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_NAPTR) String() string {
	return rr.Hdr.String() +
		strconv.Itoa(int(rr.Order)) + " " +
		strconv.Itoa(int(rr.Pref)) + " " +
		"\"" + rr.Flags + "\" " +
		"\"" + rr.Service + "\" " +
		"\"" + rr.Regexp + "\" " +
		rr.Replacement
}

func (rr *RR_NAPTR) Len() int {
	return rr.Hdr.Len() + 4 + len(rr.Flags) + len(rr.Service) +
		len(rr.Regexp) + len(rr.Replacement) + 1
}

func (rr *RR_NAPTR) Copy() RR {
	return &RR_NAPTR{*rr.Hdr.CopyHeader(), rr.Order, rr.Pref, rr.Flags, rr.Service, rr.Regexp, rr.Replacement}
}

// See RFC 4398.
type RR_CERT struct {
	Hdr         RR_Header
	Type        uint16
	KeyTag      uint16
	Algorithm   uint8
	Certificate string `dns:"base64"`
}

func (rr *RR_CERT) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_CERT) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Type)) +
		" " + strconv.Itoa(int(rr.KeyTag)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + rr.Certificate
}

func (rr *RR_CERT) Len() int {
	return rr.Hdr.Len() + 5 +
		base64.StdEncoding.DecodedLen(len(rr.Certificate))
}

func (rr *RR_CERT) Copy() RR {
	return &RR_CERT{*rr.Hdr.CopyHeader(), rr.Type, rr.KeyTag, rr.Algorithm, rr.Certificate}
}

// See RFC 2672.
type RR_DNAME struct {
	Hdr    RR_Header
	Target string `dns:"domain-name"`
}

func (rr *RR_DNAME) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_DNAME) String() string {
	return rr.Hdr.String() + rr.Target
}

func (rr *RR_DNAME) Len() int {
	l := len(rr.Target) + 1
	return rr.Hdr.Len() + l
}

func (rr *RR_DNAME) Copy() RR {
	return &RR_DNAME{*rr.Hdr.CopyHeader(), rr.Target}
}

type RR_A struct {
	Hdr RR_Header
	A   net.IP `dns:"a"`
}

func (rr *RR_A) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_A) String() string {
	return rr.Hdr.String() + rr.A.String()
}

func (rr *RR_A) Len() int {
	return rr.Hdr.Len() + net.IPv4len
}

func (rr *RR_A) Copy() RR {
	return &RR_A{*rr.Hdr.CopyHeader(), rr.A}
}

type RR_AAAA struct {
	Hdr  RR_Header
	AAAA net.IP `dns:"aaaa"`
}

func (rr *RR_AAAA) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_AAAA) String() string {
	return rr.Hdr.String() + rr.AAAA.String()
}

func (rr *RR_AAAA) Len() int {
	return rr.Hdr.Len() + net.IPv6len
}

func (rr *RR_AAAA) Copy() RR {
	return &RR_AAAA{*rr.Hdr.CopyHeader(), rr.AAAA}
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

func (rr *RR_LOC) Len() int {
	return rr.Hdr.Len() + 4 + 12
}

func (rr *RR_LOC) Copy() RR {
	return &RR_LOC{*rr.Hdr.CopyHeader(), rr.Version, rr.Size, rr.HorizPre, rr.VertPre, rr.Latitude, rr.Longitude, rr.Altitude}
}

type RR_RRSIG struct {
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

func (rr *RR_RRSIG) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_RRSIG) String() string {
	return rr.Hdr.String() + Rr_str[rr.TypeCovered] +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + strconv.Itoa(int(rr.Labels)) +
		" " + strconv.FormatInt(int64(rr.OrigTtl), 10) +
		" " + TimeToString(rr.Expiration) +
		" " + TimeToString(rr.Inception) +
		" " + strconv.Itoa(int(rr.KeyTag)) +
		" " + rr.SignerName +
		" " + rr.Signature
}

func (rr *RR_RRSIG) Len() int {
	return rr.Hdr.Len() + len(rr.SignerName) + 1 +
		base64.StdEncoding.DecodedLen(len(rr.Signature)) + 18
}

func (rr *RR_RRSIG) Copy() RR {
	return &RR_RRSIG{*rr.Hdr.CopyHeader(), rr.TypeCovered, rr.Algorithm, rr.Labels, rr.OrigTtl, rr.Expiration, rr.Inception, rr.KeyTag, rr.SignerName, rr.Signature}
}

type RR_NSEC struct {
	Hdr        RR_Header
	NextDomain string   `dns:"domain-name"`
	TypeBitMap []uint16 `dns:"nsec"`
}

func (rr *RR_NSEC) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_NSEC) String() string {
	s := rr.Hdr.String() + rr.NextDomain
	for i := 0; i < len(rr.TypeBitMap); i++ {
		if _, ok := Rr_str[rr.TypeBitMap[i]]; ok {
			s += " " + Rr_str[rr.TypeBitMap[i]]
		} else {
			s += " " + "TYPE" + strconv.Itoa(int(rr.TypeBitMap[i]))
		}
	}
	return s
}

func (rr *RR_NSEC) Len() int {
	l := len(rr.NextDomain) + 1
	return rr.Hdr.Len() + l + 32 + 1
	// TODO: +32 is max type bitmap
}

func (rr *RR_NSEC) Copy() RR {
	return &RR_NSEC{*rr.Hdr.CopyHeader(), rr.NextDomain, rr.TypeBitMap}
}

type RR_DS struct {
	Hdr        RR_Header
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string `dns:"hex"`
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

func (rr *RR_DS) Len() int {
	return rr.Hdr.Len() + 4 + len(rr.Digest)/2
}

func (rr *RR_DS) Copy() RR {
	return &RR_DS{*rr.Hdr.CopyHeader(), rr.KeyTag, rr.Algorithm, rr.DigestType, rr.Digest}
}

type RR_DLV struct {
	Hdr        RR_Header
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string `dns:"hex"`
}

func (rr *RR_DLV) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_DLV) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.KeyTag)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + strconv.Itoa(int(rr.DigestType)) +
		" " + strings.ToUpper(rr.Digest)
}

func (rr *RR_DLV) Len() int {
	return rr.Hdr.Len() + 4 + len(rr.Digest)/2
}

func (rr *RR_DLV) Copy() RR {
	return &RR_DLV{*rr.Hdr.CopyHeader(), rr.KeyTag, rr.Algorithm, rr.DigestType, rr.Digest}
}

type RR_KX struct {
	Hdr       RR_Header
	Pref      uint16
	Exchanger string `dns:"domain-name"`
}

func (rr *RR_KX) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_KX) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Pref)) +
		" " + rr.Exchanger
}

func (rr *RR_KX) Len() int {
	return 0
}

func (rr *RR_KX) Copy() RR {
	return &RR_KX{*rr.Hdr.CopyHeader(), rr.Pref, rr.Exchanger}
}

type RR_TA struct {
	Hdr        RR_Header
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string `dns:"hex"`
}

func (rr *RR_TA) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_TA) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.KeyTag)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + strconv.Itoa(int(rr.DigestType)) +
		" " + strings.ToUpper(rr.Digest)
}

func (rr *RR_TA) Len() int {
	return rr.Hdr.Len() + 4 + len(rr.Digest)/2
}

func (rr *RR_TA) Copy() RR {
	return &RR_TA{*rr.Hdr.CopyHeader(), rr.KeyTag, rr.Algorithm, rr.DigestType, rr.Digest}
}

type RR_TALINK struct {
	Hdr          RR_Header
	PreviousName string `dns:"domain"`
	NextName     string `dns:"domain"`
}

func (rr *RR_TALINK) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_TALINK) String() string {
	return rr.Hdr.String() +
		" " + rr.PreviousName + " " + rr.NextName
}

func (rr *RR_TALINK) Len() int {
	return rr.Hdr.Len() + len(rr.PreviousName) + len(rr.NextName) + 2
}

func (rr *RR_TALINK) Copy() RR {
	return &RR_TALINK{*rr.Hdr.CopyHeader(), rr.PreviousName, rr.NextName}
}

type RR_SSHFP struct {
	Hdr         RR_Header
	Algorithm   uint8
	Type        uint8
	FingerPrint string `dns:"hex"`
}

func (rr *RR_SSHFP) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_SSHFP) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Algorithm)) +
		" " + strconv.Itoa(int(rr.Type)) +
		" " + strings.ToUpper(rr.FingerPrint)
}

func (rr *RR_SSHFP) Len() int {
	return rr.Hdr.Len() + 2 + len(rr.FingerPrint)/2
}

func (rr *RR_SSHFP) Copy() RR {
	return &RR_SSHFP{*rr.Hdr.CopyHeader(), rr.Algorithm, rr.Type, rr.FingerPrint}
}

type RR_IPSECKEY struct {
	Hdr         RR_Header
	Precedence  uint8
	GatewayType uint8
	Algorithm   uint8
	Gateway     string `dns:"ipseckey"`
	PublicKey   string `dns:"base64"`
}

func (rr *RR_IPSECKEY) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_IPSECKEY) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Precedence)) +
		" " + strconv.Itoa(int(rr.GatewayType)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + rr.Gateway +
		" " + rr.PublicKey
}

func (rr *RR_IPSECKEY) Len() int {
	return rr.Hdr.Len() + 3 + len(rr.Gateway) + 1 +
		base64.StdEncoding.DecodedLen(len(rr.PublicKey))
}

func (rr *RR_IPSECKEY) Copy() RR {
	return &RR_IPSECKEY{*rr.Hdr.CopyHeader(), rr.Precedence, rr.GatewayType, rr.Algorithm, rr.Gateway, rr.PublicKey}
}

type RR_DNSKEY struct {
	Hdr       RR_Header
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey string `dns:"base64"`
}

func (rr *RR_DNSKEY) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_DNSKEY) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Flags)) +
		" " + strconv.Itoa(int(rr.Protocol)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + rr.PublicKey
}

func (rr *RR_DNSKEY) Len() int {
	return rr.Hdr.Len() + 4 +
		base64.StdEncoding.DecodedLen(len(rr.PublicKey))
}

func (rr *RR_DNSKEY) Copy() RR {
	return &RR_DNSKEY{*rr.Hdr.CopyHeader(), rr.Flags, rr.Protocol, rr.Algorithm, rr.PublicKey}
}

type RR_NSEC3 struct {
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

func (rr *RR_NSEC3) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_NSEC3) String() string {
	s := rr.Hdr.String()
	s += strconv.Itoa(int(rr.Hash)) +
		" " + strconv.Itoa(int(rr.Flags)) +
		" " + strconv.Itoa(int(rr.Iterations)) +
		" " + saltString(rr.Salt) +
		" " + rr.NextDomain
	for i := 0; i < len(rr.TypeBitMap); i++ {
		if _, ok := Rr_str[rr.TypeBitMap[i]]; ok {
			s += " " + Rr_str[rr.TypeBitMap[i]]
		} else {
			s += " " + "TYPE" + strconv.Itoa(int(rr.TypeBitMap[i]))
		}
	}
	return s
}

func (rr *RR_NSEC3) Len() int {
	return rr.Hdr.Len() + 6 + len(rr.Salt)/2 + 1 + len(rr.NextDomain) + 1 + 32
	// TODO: +32 is MAX type bit map
}

func (rr *RR_NSEC3) Copy() RR {
	return &RR_NSEC3{*rr.Hdr.CopyHeader(), rr.Hash, rr.Flags, rr.Iterations, rr.SaltLength, rr.Salt, rr.HashLength, rr.NextDomain, rr.TypeBitMap}
}

type RR_NSEC3PARAM struct {
	Hdr        RR_Header
	Hash       uint8
	Flags      uint8
	Iterations uint16
	SaltLength uint8
	Salt       string `dns:"hex"`
}

func (rr *RR_NSEC3PARAM) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_NSEC3PARAM) String() string {
	s := rr.Hdr.String()
	s += strconv.Itoa(int(rr.Hash)) +
		" " + strconv.Itoa(int(rr.Flags)) +
		" " + strconv.Itoa(int(rr.Iterations)) +
		" " + saltString(rr.Salt)
	return s
}

func (rr *RR_NSEC3PARAM) Len() int {
	return rr.Hdr.Len() + 2 + 4 + 1 + len(rr.Salt)/2
}

func (rr *RR_NSEC3PARAM) Copy() RR {
	return &RR_NSEC3PARAM{*rr.Hdr.CopyHeader(), rr.Hash, rr.Flags, rr.Iterations, rr.SaltLength, rr.Salt}
}

type RR_TKEY struct {
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

func (rr *RR_TKEY) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_TKEY) String() string {
	// It has no presentation format
	return ""
}

func (rr *RR_TKEY) Len() int {
	return rr.Hdr.Len() + len(rr.Algorithm) + 1 + 4 + 4 + 6 +
		len(rr.Key) + 2 + len(rr.OtherData)
}

func (rr *RR_TKEY) Copy() RR {
	return &RR_TKEY{*rr.Hdr.CopyHeader(), rr.Algorithm, rr.Inception, rr.Expiration, rr.Mode, rr.Error, rr.KeySize, rr.Key, rr.OtherLen, rr.OtherData}
}

// RR_RFC3597 representes an unknown RR.
type RR_RFC3597 struct {
	Hdr   RR_Header
	Rdata string `dns:"hex"`
}

func (rr *RR_RFC3597) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_RFC3597) String() string {
	s := rr.Hdr.String()
	s += "\\# " + strconv.Itoa(len(rr.Rdata)/2) + " " + rr.Rdata
	return s
}

func (rr *RR_RFC3597) Len() int {
	return rr.Hdr.Len() + len(rr.Rdata)/2
}

func (rr *RR_RFC3597) Copy() RR {
	return &RR_RFC3597{*rr.Hdr.CopyHeader(), rr.Rdata}
}

type RR_URI struct {
	Hdr      RR_Header
	Priority uint16
	Weight   uint16
	Target   string `dns:"txt"`
}

func (rr *RR_URI) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_URI) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Priority)) +
		" " + strconv.Itoa(int(rr.Weight)) +
		" " + rr.Target
}

func (rr *RR_URI) Len() int {
	return rr.Hdr.Len() + 4 + len(rr.Target) + 1
}

func (rr *RR_URI) Copy() RR {
	return &RR_URI{*rr.Hdr.CopyHeader(), rr.Weight, rr.Priority, rr.Target}
}

type RR_DHCID struct {
	Hdr    RR_Header
	Digest string `dns:"base64"`
}

func (rr *RR_DHCID) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_DHCID) String() string {
	return rr.Hdr.String() + rr.Digest
}

func (rr *RR_DHCID) Len() int {
	return rr.Hdr.Len() +
		base64.StdEncoding.DecodedLen(len(rr.Digest))
}

func (rr *RR_DHCID) Copy() RR {
	return &RR_DHCID{*rr.Hdr.CopyHeader(), rr.Digest}
}

type RR_TLSA struct {
	Hdr          RR_Header
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	Certificate  string `dns:"hex"`
}

func (rr *RR_TLSA) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_TLSA) String() string {
	return rr.Hdr.String() +
		" " + strconv.Itoa(int(rr.Usage)) +
		" " + strconv.Itoa(int(rr.Selector)) +
		" " + strconv.Itoa(int(rr.MatchingType)) +
		" " + rr.Certificate
}

func (rr *RR_TLSA) Len() int {
	return rr.Hdr.Len() + 3 + len(rr.Certificate)/2
}

func (rr *RR_TLSA) Copy() RR {
	return &RR_TLSA{*rr.Hdr.CopyHeader(), rr.Usage, rr.Selector, rr.MatchingType, rr.Certificate}
}

type RR_HIP struct {
	Hdr                RR_Header
	HitLength          uint8
	PublicKeyAlgorithm uint8
	PublicKeyLength    uint16
	Hit                string   `dns:"hex"`
	PublicKey          string   `dns:"base64"`
	RendezvousServers  []string `dns:"domain-name"`
}

func (rr *RR_HIP) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_HIP) String() string {
	s := rr.Hdr.String() +
		" " + strconv.Itoa(int(rr.PublicKeyAlgorithm)) +
		" " + rr.Hit +
		" " + rr.PublicKey
	for _, d := range rr.RendezvousServers {
		s += " " + d
	}
	return s
}

func (rr *RR_HIP) Len() int {
	l := rr.Hdr.Len() + 4 +
		len(rr.Hit)/2 +
		base64.StdEncoding.DecodedLen(len(rr.PublicKey))
	for _, d := range rr.RendezvousServers {
		l += len(d) + 1
	}
	return l
}

func (rr *RR_HIP) Copy() RR {
	return &RR_HIP{*rr.Hdr.CopyHeader(), rr.HitLength, rr.PublicKeyAlgorithm, rr.PublicKeyLength, rr.Hit, rr.PublicKey, rr.RendezvousServers}
}

type RR_WKS struct {
	Hdr      RR_Header
	Address  net.IP `dns:"a"`
	Protocol uint8
	BitMap   []uint16 `dns:"wks"`
}

func (rr *RR_WKS) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_WKS) String() string {
	s := rr.Hdr.String() + rr.Address.String()
	for i := 0; i < len(rr.BitMap); i++ {
		// should lookup the port
		s += " " + strconv.Itoa(int(rr.BitMap[i]))
	}
	return s
}

func (rr *RR_WKS) Len() int {
	return rr.Hdr.Len() + net.IPv4len + 1
}

func (rr *RR_WKS) Copy() RR {
	return &RR_WKS{*rr.Hdr.CopyHeader(), rr.Address, rr.Protocol, rr.BitMap}
}

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

// saltString converts a NSECX salt to uppercase and
// returns "-" when it is empty
func saltString(s string) string {
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

// Map of constructors for each RR wire type.
var rr_mk = map[uint16]func() RR{
	TypeCNAME:      func() RR { return new(RR_CNAME) },
	TypeHINFO:      func() RR { return new(RR_HINFO) },
	TypeMB:         func() RR { return new(RR_MB) },
	TypeMG:         func() RR { return new(RR_MG) },
	TypeMD:         func() RR { return new(RR_MD) },
	TypeMF:         func() RR { return new(RR_MF) },
	TypeMINFO:      func() RR { return new(RR_MINFO) },
	TypeRP:         func() RR { return new(RR_RP) },
	TypeAFSDB:      func() RR { return new(RR_AFSDB) },
	TypeMR:         func() RR { return new(RR_MR) },
	TypeMX:         func() RR { return new(RR_MX) },
	TypeNS:         func() RR { return new(RR_NS) },
	TypePTR:        func() RR { return new(RR_PTR) },
	TypeSOA:        func() RR { return new(RR_SOA) },
	TypeRT:         func() RR { return new(RR_RT) },
	TypeTXT:        func() RR { return new(RR_TXT) },
	TypeSRV:        func() RR { return new(RR_SRV) },
	TypeNAPTR:      func() RR { return new(RR_NAPTR) },
	TypeDNAME:      func() RR { return new(RR_DNAME) },
	TypeA:          func() RR { return new(RR_A) },
	TypeWKS:        func() RR { return new(RR_WKS) },
	TypeAAAA:       func() RR { return new(RR_AAAA) },
	TypeLOC:        func() RR { return new(RR_LOC) },
	TypeOPT:        func() RR { return new(RR_OPT) },
	TypeDS:         func() RR { return new(RR_DS) },
	TypeCERT:       func() RR { return new(RR_CERT) },
	TypeKX:         func() RR { return new(RR_KX) },
	TypeSPF:        func() RR { return new(RR_SPF) },
	TypeTALINK:     func() RR { return new(RR_TALINK) },
	TypeSSHFP:      func() RR { return new(RR_SSHFP) },
	TypeRRSIG:      func() RR { return new(RR_RRSIG) },
	TypeNSEC:       func() RR { return new(RR_NSEC) },
	TypeDNSKEY:     func() RR { return new(RR_DNSKEY) },
	TypeNSEC3:      func() RR { return new(RR_NSEC3) },
	TypeDHCID:      func() RR { return new(RR_DHCID) },
	TypeNSEC3PARAM: func() RR { return new(RR_NSEC3PARAM) },
	TypeTKEY:       func() RR { return new(RR_TKEY) },
	TypeTSIG:       func() RR { return new(RR_TSIG) },
	TypeURI:        func() RR { return new(RR_URI) },
	TypeTA:         func() RR { return new(RR_TA) },
	TypeDLV:        func() RR { return new(RR_DLV) },
	TypeTLSA:       func() RR { return new(RR_TLSA) },
	TypeHIP:        func() RR { return new(RR_HIP) },
}
