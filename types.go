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
	TypeNID        uint16 = 104
	TypeL32        uint16 = 105
	TypeL64        uint16 = 106
	TypeLP         uint16 = 107

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
	if _, ok := ClassToString[q.Qclass]; ok {
		s += ClassToString[q.Qclass] + "\t"
	} else {
		s += "CLASS" + strconv.Itoa(int(q.Qtype))
	}

	if _, ok := TypeToString[q.Qtype]; ok {
		s += " " + TypeToString[q.Qtype]
	} else {
		s += " " + "TYPE" + strconv.Itoa(int(q.Qtype))
	}
	return s
}

func (q *Question) Len() int {
	l := len(q.Name) + 1
	return l + 4
}

type ANY struct {
	Hdr RR_Header
	// Does not have any rdata
}

func (rr *ANY) Header() *RR_Header { return &rr.Hdr }
func (rr *ANY) Copy() RR           { return &ANY{*rr.Hdr.CopyHeader()} }

func (rr *ANY) String() string {
	return rr.Hdr.String()
}

func (rr *ANY) Len() int {
	return rr.Hdr.Len()
}

type CNAME struct {
	Hdr    RR_Header
	Target string `dns:"cdomain-name"`
}

func (rr *CNAME) Header() *RR_Header { return &rr.Hdr }
func (rr *CNAME) Copy() RR           { return &CNAME{*rr.Hdr.CopyHeader(), rr.Target} }

func (rr *CNAME) String() string {
	return rr.Hdr.String() + rr.Target
}

func (rr *CNAME) Len() int {
	l := len(rr.Target) + 1
	return rr.Hdr.Len() + l
}

type HINFO struct {
	Hdr RR_Header
	Cpu string
	Os  string
}

func (rr *HINFO) Header() *RR_Header { return &rr.Hdr }
func (rr *HINFO) Copy() RR           { return &HINFO{*rr.Hdr.CopyHeader(), rr.Cpu, rr.Os} }

func (rr *HINFO) String() string {
	return rr.Hdr.String() + rr.Cpu + " " + rr.Os
}

func (rr *HINFO) Len() int {
	return rr.Hdr.Len() + len(rr.Cpu) + len(rr.Os)
}

type MB struct {
	Hdr RR_Header
	Mb  string `dns:"cdomain-name"`
}

func (rr *MB) Header() *RR_Header { return &rr.Hdr }
func (rr *MB) Copy() RR           { return &MB{*rr.Hdr.CopyHeader(), rr.Mb} }

func (rr *MB) String() string {
	return rr.Hdr.String() + rr.Mb
}

func (rr *MB) Len() int {
	l := len(rr.Mb) + 1
	return rr.Hdr.Len() + l
}

type MG struct {
	Hdr RR_Header
	Mg  string `dns:"cdomain-name"`
}

func (rr *MG) Header() *RR_Header { return &rr.Hdr }
func (rr *MG) Copy() RR           { return &MG{*rr.Hdr.CopyHeader(), rr.Mg} }

func (rr *MG) String() string {
	return rr.Hdr.String() + rr.Mg
}

func (rr *MG) Len() int {
	l := len(rr.Mg) + 1
	return rr.Hdr.Len() + l
}

type MINFO struct {
	Hdr   RR_Header
	Rmail string `dns:"cdomain-name"`
	Email string `dns:"cdomain-name"`
}

func (rr *MINFO) Header() *RR_Header { return &rr.Hdr }
func (rr *MINFO) Copy() RR           { return &MINFO{*rr.Hdr.CopyHeader(), rr.Rmail, rr.Email} }

func (rr *MINFO) String() string {
	return rr.Hdr.String() + rr.Rmail + " " + rr.Email
}

func (rr *MINFO) Len() int {
	l := len(rr.Rmail) + 1
	n := len(rr.Email) + 1
	return rr.Hdr.Len() + l + n
}

type MR struct {
	Hdr RR_Header
	Mr  string `dns:"cdomain-name"`
}

func (rr *MR) Header() *RR_Header { return &rr.Hdr }
func (rr *MR) Copy() RR           { return &MR{*rr.Hdr.CopyHeader(), rr.Mr} }

func (rr *MR) String() string {
	return rr.Hdr.String() + rr.Mr
}

func (rr *MR) Len() int {
	l := len(rr.Mr) + 1
	return rr.Hdr.Len() + l
}

type MF struct {
	Hdr RR_Header
	Mf  string `dns:"cdomain-name"`
}

func (rr *MF) Header() *RR_Header { return &rr.Hdr }
func (rr *MF) Copy() RR           { return &MF{*rr.Hdr.CopyHeader(), rr.Mf} }

func (rr *MF) String() string {
	return rr.Hdr.String() + " " + rr.Mf
}

func (rr *MF) Len() int {
	return rr.Hdr.Len() + len(rr.Mf) + 1
}

type MD struct {
	Hdr RR_Header
	Md  string `dns:"cdomain-name"`
}

func (rr *MD) Header() *RR_Header { return &rr.Hdr }
func (rr *MD) Copy() RR           { return &MD{*rr.Hdr.CopyHeader(), rr.Md} }

func (rr *MD) String() string {
	return rr.Hdr.String() + " " + rr.Md
}

func (rr *MD) Len() int {
	return rr.Hdr.Len() + len(rr.Md) + 1
}

type MX struct {
	Hdr        RR_Header
	Preference uint16
	Mx         string `dns:"cdomain-name"`
}

func (rr *MX) Header() *RR_Header { return &rr.Hdr }
func (rr *MX) Copy() RR           { return &MX{*rr.Hdr.CopyHeader(), rr.Preference, rr.Mx} }

func (rr *MX) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Preference)) + " " + rr.Mx
}

func (rr *MX) Len() int {
	l := len(rr.Mx) + 1
	return rr.Hdr.Len() + l + 2
}

type AFSDB struct {
	Hdr      RR_Header
	Subtype  uint16
	Hostname string `dns:"cdomain-name"`
}

func (rr *AFSDB) Header() *RR_Header { return &rr.Hdr }
func (rr *AFSDB) Copy() RR           { return &AFSDB{*rr.Hdr.CopyHeader(), rr.Subtype, rr.Hostname} }

func (rr *AFSDB) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Subtype)) + " " + rr.Hostname
}

func (rr *AFSDB) Len() int {
	l := len(rr.Hostname) + 1
	return rr.Hdr.Len() + l + 2
}

type X25 struct {
	Hdr         RR_Header
	PSDNAddress string
}

func (rr *X25) Header() *RR_Header { return &rr.Hdr }
func (rr *X25) Copy() RR           { return &X25{*rr.Hdr.CopyHeader(), rr.PSDNAddress} }

func (rr *X25) String() string {
	return rr.Hdr.String() + rr.PSDNAddress
}

func (rr *X25) Len() int {
	return rr.Hdr.Len() + len(rr.PSDNAddress)
}

type RT struct {
	Hdr        RR_Header
	Preference uint16
	Host       string `dns:"cdomain-name"`
}

func (rr *RT) Header() *RR_Header { return &rr.Hdr }
func (rr *RT) Copy() RR           { return &RT{*rr.Hdr.CopyHeader(), rr.Preference, rr.Host} }

func (rr *RT) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Preference)) + " " + rr.Host
}

func (rr *RT) Len() int {
	l := len(rr.Host) + 1
	return rr.Hdr.Len() + l + 2
}

type NS struct {
	Hdr RR_Header
	Ns  string `dns:"cdomain-name"`
}

func (rr *NS) Header() *RR_Header { return &rr.Hdr }
func (rr *NS) Copy() RR           { return &NS{*rr.Hdr.CopyHeader(), rr.Ns} }

func (rr *NS) String() string {
	return rr.Hdr.String() + rr.Ns
}

func (rr *NS) Len() int {
	l := len(rr.Ns) + 1
	return rr.Hdr.Len() + l
}

type PTR struct {
	Hdr RR_Header
	Ptr string `dns:"cdomain-name"`
}

func (rr *PTR) Header() *RR_Header { return &rr.Hdr }
func (rr *PTR) Copy() RR           { return &PTR{*rr.Hdr.CopyHeader(), rr.Ptr} }

func (rr *PTR) String() string {
	return rr.Hdr.String() + rr.Ptr
}

func (rr *PTR) Len() int {
	l := len(rr.Ptr) + 1
	return rr.Hdr.Len() + l
}

type RP struct {
	Hdr  RR_Header
	Mbox string `dns:"domain-name"`
	Txt  string `dns:"domain-name"`
}

func (rr *RP) Header() *RR_Header { return &rr.Hdr }
func (rr *RP) Copy() RR           { return &RP{*rr.Hdr.CopyHeader(), rr.Mbox, rr.Txt} }

func (rr *RP) String() string {
	return rr.Hdr.String() + rr.Mbox + " " + rr.Txt
}

func (rr *RP) Len() int {
	return rr.Hdr.Len() + len(rr.Mbox) + 1 + len(rr.Txt) + 1
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
func (rr *SOA) Copy() RR {
	return &SOA{*rr.Hdr.CopyHeader(), rr.Ns, rr.Mbox, rr.Serial, rr.Refresh, rr.Retry, rr.Expire, rr.Minttl}
}

func (rr *SOA) String() string {
	return rr.Hdr.String() + rr.Ns + " " + rr.Mbox +
		" " + strconv.FormatInt(int64(rr.Serial), 10) +
		" " + strconv.FormatInt(int64(rr.Refresh), 10) +
		" " + strconv.FormatInt(int64(rr.Retry), 10) +
		" " + strconv.FormatInt(int64(rr.Expire), 10) +
		" " + strconv.FormatInt(int64(rr.Minttl), 10)
}

func (rr *SOA) Len() int {
	l := len(rr.Ns) + 1
	n := len(rr.Mbox) + 1
	return rr.Hdr.Len() + l + n + 20
}

type TXT struct {
	Hdr RR_Header
	Txt []string `dns:"txt"`
}

func (rr *TXT) Header() *RR_Header { return &rr.Hdr }
func (rr *TXT) Copy() RR           { return &TXT{*rr.Hdr.CopyHeader(), rr.Txt} }

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

func (rr *TXT) Len() int {
	l := rr.Hdr.Len()
	for _, t := range rr.Txt {
		l += len(t)
	}
	return l
}

type SPF struct {
	Hdr RR_Header
	Txt []string `dns:"txt"`
}

func (rr *SPF) Header() *RR_Header { return &rr.Hdr }
func (rr *SPF) Copy() RR           { return &SPF{*rr.Hdr.CopyHeader(), rr.Txt} }

func (rr *SPF) String() string {
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

func (rr *SPF) Len() int {
	l := rr.Hdr.Len()
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
func (rr *SRV) Copy() RR {
	return &SRV{*rr.Hdr.CopyHeader(), rr.Priority, rr.Weight, rr.Port, rr.Target}
}

func (rr *SRV) String() string {
	return rr.Hdr.String() +
		strconv.Itoa(int(rr.Priority)) + " " +
		strconv.Itoa(int(rr.Weight)) + " " +
		strconv.Itoa(int(rr.Port)) + " " + rr.Target
}

func (rr *SRV) Len() int {
	l := len(rr.Target) + 1
	return rr.Hdr.Len() + l + 6
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
func (rr *NAPTR) Copy() RR {
	return &NAPTR{*rr.Hdr.CopyHeader(), rr.Order, rr.Preference, rr.Flags, rr.Service, rr.Regexp, rr.Replacement}
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

func (rr *NAPTR) Len() int {
	return rr.Hdr.Len() + 4 + len(rr.Flags) + len(rr.Service) +
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
func (rr *CERT) Copy() RR {
	return &CERT{*rr.Hdr.CopyHeader(), rr.Type, rr.KeyTag, rr.Algorithm, rr.Certificate}
}

func (rr *CERT) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Type)) +
		" " + strconv.Itoa(int(rr.KeyTag)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + rr.Certificate
}

func (rr *CERT) Len() int {
	return rr.Hdr.Len() + 5 +
		base64.StdEncoding.DecodedLen(len(rr.Certificate))
}

// See RFC 2672.
type DNAME struct {
	Hdr    RR_Header
	Target string `dns:"domain-name"`
}

func (rr *DNAME) Header() *RR_Header { return &rr.Hdr }
func (rr *DNAME) Copy() RR           { return &DNAME{*rr.Hdr.CopyHeader(), rr.Target} }

func (rr *DNAME) String() string {
	return rr.Hdr.String() + rr.Target
}

func (rr *DNAME) Len() int {
	l := len(rr.Target) + 1
	return rr.Hdr.Len() + l
}

type A struct {
	Hdr RR_Header
	A   net.IP `dns:"a"`
}

func (rr *A) Header() *RR_Header { return &rr.Hdr }
func (rr *A) Copy() RR           { return &A{*rr.Hdr.CopyHeader(), rr.A} }

func (rr *A) String() string {
	return rr.Hdr.String() + rr.A.String()
}

func (rr *A) Len() int {
	return rr.Hdr.Len() + net.IPv4len
}

type AAAA struct {
	Hdr  RR_Header
	AAAA net.IP `dns:"aaaa"`
}

func (rr *AAAA) Header() *RR_Header { return &rr.Hdr }
func (rr *AAAA) Copy() RR           { return &AAAA{*rr.Hdr.CopyHeader(), rr.AAAA} }

func (rr *AAAA) String() string {
	return rr.Hdr.String() + rr.AAAA.String()
}

func (rr *AAAA) Len() int {
	return rr.Hdr.Len() + net.IPv6len
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
func (rr *LOC) Copy() RR {
	return &LOC{*rr.Hdr.CopyHeader(), rr.Version, rr.Size, rr.HorizPre, rr.VertPre, rr.Latitude, rr.Longitude, rr.Altitude}
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

func (rr *LOC) Len() int {
	return rr.Hdr.Len() + 4 + 12
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
func (rr *RRSIG) Copy() RR {
	return &RRSIG{*rr.Hdr.CopyHeader(), rr.TypeCovered, rr.Algorithm, rr.Labels, rr.OrigTtl, rr.Expiration, rr.Inception, rr.KeyTag, rr.SignerName, rr.Signature}
}

func (rr *RRSIG) String() string {
	return rr.Hdr.String() + TypeToString[rr.TypeCovered] +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + strconv.Itoa(int(rr.Labels)) +
		" " + strconv.FormatInt(int64(rr.OrigTtl), 10) +
		" " + TimeToString(rr.Expiration) +
		" " + TimeToString(rr.Inception) +
		" " + strconv.Itoa(int(rr.KeyTag)) +
		" " + rr.SignerName +
		" " + rr.Signature
}

func (rr *RRSIG) Len() int {
	return rr.Hdr.Len() + len(rr.SignerName) + 1 +
		base64.StdEncoding.DecodedLen(len(rr.Signature)) + 18
}

type NSEC struct {
	Hdr        RR_Header
	NextDomain string   `dns:"domain-name"`
	TypeBitMap []uint16 `dns:"nsec"`
}

func (rr *NSEC) Header() *RR_Header { return &rr.Hdr }
func (rr *NSEC) Copy() RR           { return &NSEC{*rr.Hdr.CopyHeader(), rr.NextDomain, rr.TypeBitMap} }

func (rr *NSEC) String() string {
	s := rr.Hdr.String() + rr.NextDomain
	for i := 0; i < len(rr.TypeBitMap); i++ {
		if _, ok := TypeToString[rr.TypeBitMap[i]]; ok {
			s += " " + TypeToString[rr.TypeBitMap[i]]
		} else {
			s += " " + "TYPE" + strconv.Itoa(int(rr.TypeBitMap[i]))
		}
	}
	return s
}

func (rr *NSEC) Len() int {
	l := len(rr.NextDomain) + 1
	return rr.Hdr.Len() + l + 32 + 1
	// TODO: +32 is max type bitmap
}

type DS struct {
	Hdr        RR_Header
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string `dns:"hex"`
}

func (rr *DS) Header() *RR_Header { return &rr.Hdr }
func (rr *DS) Copy() RR {
	return &DS{*rr.Hdr.CopyHeader(), rr.KeyTag, rr.Algorithm, rr.DigestType, rr.Digest}
}

func (rr *DS) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.KeyTag)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + strconv.Itoa(int(rr.DigestType)) +
		" " + strings.ToUpper(rr.Digest)
}

func (rr *DS) Len() int {
	return rr.Hdr.Len() + 4 + len(rr.Digest)/2
}

type CDS struct {
	Hdr        RR_Header
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string `dns:"hex"`
}

func (rr *CDS) Header() *RR_Header { return &rr.Hdr }
func (rr *CDS) Copy() RR {
	return &CDS{*rr.Hdr.CopyHeader(), rr.KeyTag, rr.Algorithm, rr.DigestType, rr.Digest}
}

func (rr *CDS) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.KeyTag)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + strconv.Itoa(int(rr.DigestType)) +
		" " + strings.ToUpper(rr.Digest)
}

func (rr *CDS) Len() int {
	return rr.Hdr.Len() + 4 + len(rr.Digest)/2
}

type DLV struct {
	Hdr        RR_Header
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string `dns:"hex"`
}

func (rr *DLV) Header() *RR_Header { return &rr.Hdr }
func (rr *DLV) Copy() RR {
	return &DLV{*rr.Hdr.CopyHeader(), rr.KeyTag, rr.Algorithm, rr.DigestType, rr.Digest}
}

func (rr *DLV) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.KeyTag)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + strconv.Itoa(int(rr.DigestType)) +
		" " + strings.ToUpper(rr.Digest)
}

func (rr *DLV) Len() int {
	return rr.Hdr.Len() + 4 + len(rr.Digest)/2
}

type KX struct {
	Hdr        RR_Header
	Preference uint16
	Exchanger  string `dns:"domain-name"`
}

func (rr *KX) Header() *RR_Header { return &rr.Hdr }
func (rr *KX) Copy() RR           { return &KX{*rr.Hdr.CopyHeader(), rr.Preference, rr.Exchanger} }

func (rr *KX) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Preference)) +
		" " + rr.Exchanger
}

func (rr *KX) Len() int {
	return 0
}

type TA struct {
	Hdr        RR_Header
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string `dns:"hex"`
}

func (rr *TA) Header() *RR_Header { return &rr.Hdr }
func (rr *TA) Copy() RR {
	return &TA{*rr.Hdr.CopyHeader(), rr.KeyTag, rr.Algorithm, rr.DigestType, rr.Digest}
}

func (rr *TA) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.KeyTag)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + strconv.Itoa(int(rr.DigestType)) +
		" " + strings.ToUpper(rr.Digest)
}

func (rr *TA) Len() int {
	return rr.Hdr.Len() + 4 + len(rr.Digest)/2
}

type TALINK struct {
	Hdr          RR_Header
	PreviousName string `dns:"domain"`
	NextName     string `dns:"domain"`
}

func (rr *TALINK) Header() *RR_Header { return &rr.Hdr }
func (rr *TALINK) Copy() RR           { return &TALINK{*rr.Hdr.CopyHeader(), rr.PreviousName, rr.NextName} }

func (rr *TALINK) String() string {
	return rr.Hdr.String() +
		" " + rr.PreviousName + " " + rr.NextName
}

func (rr *TALINK) Len() int {
	return rr.Hdr.Len() + len(rr.PreviousName) + len(rr.NextName) + 2
}

type SSHFP struct {
	Hdr         RR_Header
	Algorithm   uint8
	Type        uint8
	FingerPrint string `dns:"hex"`
}

func (rr *SSHFP) Header() *RR_Header { return &rr.Hdr }
func (rr *SSHFP) Copy() RR {
	return &SSHFP{*rr.Hdr.CopyHeader(), rr.Algorithm, rr.Type, rr.FingerPrint}
}

func (rr *SSHFP) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Algorithm)) +
		" " + strconv.Itoa(int(rr.Type)) +
		" " + strings.ToUpper(rr.FingerPrint)
}

func (rr *SSHFP) Len() int {
	return rr.Hdr.Len() + 2 + len(rr.FingerPrint)/2
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
func (rr *IPSECKEY) Copy() RR {
	return &IPSECKEY{*rr.Hdr.CopyHeader(), rr.Precedence, rr.GatewayType, rr.Algorithm, rr.Gateway, rr.PublicKey}
}

func (rr *IPSECKEY) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Precedence)) +
		" " + strconv.Itoa(int(rr.GatewayType)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + rr.Gateway +
		" " + rr.PublicKey
}

func (rr *IPSECKEY) Len() int {
	return rr.Hdr.Len() + 3 + len(rr.Gateway) + 1 +
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
func (rr *DNSKEY) Copy() RR {
	return &DNSKEY{*rr.Hdr.CopyHeader(), rr.Flags, rr.Protocol, rr.Algorithm, rr.PublicKey}
}

func (rr *DNSKEY) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Flags)) +
		" " + strconv.Itoa(int(rr.Protocol)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + rr.PublicKey
}

func (rr *DNSKEY) Len() int {
	return rr.Hdr.Len() + 4 +
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
func (rr *RKEY) Copy() RR {
	return &RKEY{*rr.Hdr.CopyHeader(), rr.Flags, rr.Protocol, rr.Algorithm, rr.PublicKey}
}

func (rr *RKEY) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Flags)) +
		" " + strconv.Itoa(int(rr.Protocol)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + rr.PublicKey
}

func (rr *RKEY) Len() int {
	return rr.Hdr.Len() + 4 +
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
func (rr *NSEC3) Copy() RR {
	return &NSEC3{*rr.Hdr.CopyHeader(), rr.Hash, rr.Flags, rr.Iterations, rr.SaltLength, rr.Salt, rr.HashLength, rr.NextDomain, rr.TypeBitMap}
}

func (rr *NSEC3) String() string {
	s := rr.Hdr.String()
	s += strconv.Itoa(int(rr.Hash)) +
		" " + strconv.Itoa(int(rr.Flags)) +
		" " + strconv.Itoa(int(rr.Iterations)) +
		" " + saltString(rr.Salt) +
		" " + rr.NextDomain
	for i := 0; i < len(rr.TypeBitMap); i++ {
		if _, ok := TypeToString[rr.TypeBitMap[i]]; ok {
			s += " " + TypeToString[rr.TypeBitMap[i]]
		} else {
			s += " " + "TYPE" + strconv.Itoa(int(rr.TypeBitMap[i]))
		}
	}
	return s
}

func (rr *NSEC3) Len() int {
	return rr.Hdr.Len() + 6 + len(rr.Salt)/2 + 1 + len(rr.NextDomain) + 1 + 32
	// TODO: +32 is MAX type bit map
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
func (rr *NSEC3PARAM) Copy() RR {
	return &NSEC3PARAM{*rr.Hdr.CopyHeader(), rr.Hash, rr.Flags, rr.Iterations, rr.SaltLength, rr.Salt}
}

func (rr *NSEC3PARAM) String() string {
	s := rr.Hdr.String()
	s += strconv.Itoa(int(rr.Hash)) +
		" " + strconv.Itoa(int(rr.Flags)) +
		" " + strconv.Itoa(int(rr.Iterations)) +
		" " + saltString(rr.Salt)
	return s
}

func (rr *NSEC3PARAM) Len() int {
	return rr.Hdr.Len() + 2 + 4 + 1 + len(rr.Salt)/2
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
func (rr *TKEY) Copy() RR {
	return &TKEY{*rr.Hdr.CopyHeader(), rr.Algorithm, rr.Inception, rr.Expiration, rr.Mode, rr.Error, rr.KeySize, rr.Key, rr.OtherLen, rr.OtherData}
}

func (rr *TKEY) String() string {
	// It has no presentation format
	return ""
}

func (rr *TKEY) Len() int {
	return rr.Hdr.Len() + len(rr.Algorithm) + 1 + 4 + 4 + 6 +
		len(rr.Key) + 2 + len(rr.OtherData)
}

// RFC3597 representes an unknown RR.
type RFC3597 struct {
	Hdr   RR_Header
	Rdata string `dns:"hex"`
}

func (rr *RFC3597) Header() *RR_Header { return &rr.Hdr }
func (rr *RFC3597) Copy() RR           { return &RFC3597{*rr.Hdr.CopyHeader(), rr.Rdata} }

func (rr *RFC3597) String() string {
	s := rr.Hdr.String()
	s += "\\# " + strconv.Itoa(len(rr.Rdata)/2) + " " + rr.Rdata
	return s
}

func (rr *RFC3597) Len() int {
	return rr.Hdr.Len() + len(rr.Rdata)/2
}

type URI struct {
	Hdr      RR_Header
	Priority uint16
	Weight   uint16
	Target   []string `dns:"txt"`
}

func (rr *URI) Header() *RR_Header { return &rr.Hdr }
func (rr *URI) Copy() RR           { return &URI{*rr.Hdr.CopyHeader(), rr.Weight, rr.Priority, rr.Target} }

func (rr *URI) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Priority)) +
		" " + strconv.Itoa(int(rr.Weight)) +
		" " + rr.Target
}

func (rr *URI) Len() int {
	return rr.Hdr.Len() + 4 + len(rr.Target) + 1
}

type DHCID struct {
	Hdr    RR_Header
	Digest string `dns:"base64"`
}

func (rr *DHCID) Header() *RR_Header { return &rr.Hdr }
func (rr *DHCID) Copy() RR           { return &DHCID{*rr.Hdr.CopyHeader(), rr.Digest} }

func (rr *DHCID) String() string {
	return rr.Hdr.String() + rr.Digest
}

func (rr *DHCID) Len() int {
	return rr.Hdr.Len() +
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
func (rr *TLSA) Copy() RR {
	return &TLSA{*rr.Hdr.CopyHeader(), rr.Usage, rr.Selector, rr.MatchingType, rr.Certificate}
}

func (rr *TLSA) String() string {
	return rr.Hdr.String() +
		" " + strconv.Itoa(int(rr.Usage)) +
		" " + strconv.Itoa(int(rr.Selector)) +
		" " + strconv.Itoa(int(rr.MatchingType)) +
		" " + rr.Certificate
}

func (rr *TLSA) Len() int {
	return rr.Hdr.Len() + 3 + len(rr.Certificate)/2
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
func (rr *HIP) Copy() RR {
	return &HIP{*rr.Hdr.CopyHeader(), rr.HitLength, rr.PublicKeyAlgorithm, rr.PublicKeyLength, rr.Hit, rr.PublicKey, rr.RendezvousServers}
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

func (rr *HIP) Len() int {
	l := rr.Hdr.Len() + 4 +
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
func (rr *NINFO) Copy() RR           { return &NINFO{*rr.Hdr.CopyHeader(), rr.ZSData} }

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

func (rr *NINFO) Len() int {
	l := rr.Hdr.Len()
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
func (rr *WKS) Copy() RR           { return &WKS{*rr.Hdr.CopyHeader(), rr.Address, rr.Protocol, rr.BitMap} }

func (rr *WKS) String() string {
	s := rr.Hdr.String() + rr.Address.String()
	for i := 0; i < len(rr.BitMap); i++ {
		// should lookup the port
		s += " " + strconv.Itoa(int(rr.BitMap[i]))
	}
	return s
}

func (rr *WKS) Len() int {
	return rr.Hdr.Len() + net.IPv4len + 1
}

type NID struct {
	Hdr        RR_Header
	Preference uint16
	NodeID     uint64
}

func (rr *NID) Header() *RR_Header { return &rr.Hdr }
func (rr *NID) Copy() RR           { return &NID{*rr.Hdr.CopyHeader(), rr.Preference, rr.NodeID} }

func (rr *NID) String() string {
	s := rr.Hdr.String() + strconv.Itoa(int(rr.Preference))
	node := fmt.Sprintf("%0.16x", rr.NodeID)
	s += " " + node[0:4] + ":" + node[4:8] + ":" + node[8:12] + ":" + node[12:16]
	return s
}

func (rr *NID) Len() int {
	return rr.Hdr.Len() + 2 + 8
}

type L32 struct {
	Hdr        RR_Header
	Preference uint16
	Locator32  net.IP `dns:"a"`
}

func (rr *L32) Header() *RR_Header { return &rr.Hdr }
func (rr *L32) Copy() RR           { return &L32{*rr.Hdr.CopyHeader(), rr.Preference, rr.Locator32} }

func (rr *L32) String() string {
	return rr.Hdr.String() + strconv.Itoa(int(rr.Preference)) +
		" " + rr.Locator32.String()
}

func (rr *L32) Len() int {
	return rr.Hdr.Len() + net.IPv4len
}

type L64 struct {
	Hdr        RR_Header
	Preference uint16
	Locator64  uint64
}

func (rr *L64) Header() *RR_Header { return &rr.Hdr }
func (rr *L64) Copy() RR           { return &L64{*rr.Hdr.CopyHeader(), rr.Preference, rr.Locator64} }

func (rr *L64) String() string {
	s := rr.Hdr.String() + strconv.Itoa(int(rr.Preference))
	node := fmt.Sprintf("%0.16X", rr.Locator64)
	s += " " + node[0:4] + ":" + node[4:8] + ":" + node[8:12] + ":" + node[12:16]
	return s
}

func (rr *L64) Len() int {
	return rr.Hdr.Len() + 2 + 8
}

type LP struct {
	Hdr        RR_Header
	Preference uint16
	Fqdn       string `dns:"domain-name"`
}

func (rr *LP) Header() *RR_Header { return &rr.Hdr }
func (rr *LP) Copy() RR           { return &LP{*rr.Hdr.CopyHeader(), rr.Preference, rr.Fqdn} }

func (rr *LP) String() string {
	s := rr.Hdr.String() + strconv.Itoa(int(rr.Preference)) +
		" " + rr.Fqdn
	return s
}

func (rr *LP) Len() int {
	return rr.Hdr.Len() + 2 + len(rr.Fqdn) + 1
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
}
