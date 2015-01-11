// FORMAT
//
// The dns package implements String() for all RR types, but sometimes you will
// need more flexibility. The functions Printf, Sprintf, etc. implemented formatted I/O
// for the RR type.
//
// Printing
//
// The verbs:
//
// Generic part of RRs:
//
//	%N	the owner name of the RR
//	%C	the class: IN, CH, CLASS15, etc.
//	%D	the TTL in seconds
//	%Y	the type: MX, A, etc.
//
// The rdata of each RR differs, we allow each field to be printed as a string.
//
// Rdata: (TODO)
//
//	%0	the first rdata field
//	%1	the second rdata field
//	%2	the third rdata field
//	..	...
//	%9      the nineth rdata field
//	%R	all rdata fields
//
package dns

import (
	"fmt"
	"strconv"
)

func format(r RR, f fmt.State, c rune) {
	switch c {
	case 'N':
		f.Write([]byte(r.Header().Name))
	case 'C':
		f.Write([]byte(Class(r.Header().Class).String()))
	case 'D':
		f.Write([]byte(strconv.Itoa(int(r.Header().Ttl))))
	case 'Y':
		f.Write([]byte(Type(r.Header().Rrtype).String()))
	}
}

func format_Header(h *RR_Header, f fmt.State, c rune) {
	switch c {
	case 'N':
		f.Write([]byte(h.Name))
	case 'C':
		f.Write([]byte(Class(h.Class).String()))
	case 'D':
		f.Write([]byte(strconv.Itoa(int(h.Ttl))))
	case 'Y':
		f.Write([]byte(Type(h.Rrtype).String()))
	}
}

func (h *RR_Header) Format(f fmt.State, c rune)  { format_Header(h, f, c) }
func (rr *RFC3597) Format(f fmt.State, c rune)   { format(rr, f, c) }
func (rr *PrivateRR) Format(f fmt.State, c rune) { format(rr, f, c) }
func (rr *IPSECKEY) Format(f fmt.State, c rune)  { format(rr, f, c) }
func (rr *ANY) Format(f fmt.State, c rune)       { format(rr, f, c) }

// Quick 'n dirty:
// for i in $(egrep '\sType.*:.*new\(' types.go | awk '{ print $6 } ' | sed 's/new(//' | sed 's/)//'); do
// echo "func (rr *$i) Format(f fmt.State, c rune) { format(rr, f, c) }" ; done

func (rr *A) Format(f fmt.State, c rune)          { format(rr, f, c) }
func (rr *AAAA) Format(f fmt.State, c rune)       { format(rr, f, c) }
func (rr *AFSDB) Format(f fmt.State, c rune)      { format(rr, f, c) }
func (rr *CDS) Format(f fmt.State, c rune)        { format(rr, f, c) }
func (rr *CERT) Format(f fmt.State, c rune)       { format(rr, f, c) }
func (rr *CNAME) Format(f fmt.State, c rune)      { format(rr, f, c) }
func (rr *DHCID) Format(f fmt.State, c rune)      { format(rr, f, c) }
func (rr *DLV) Format(f fmt.State, c rune)        { format(rr, f, c) }
func (rr *DNAME) Format(f fmt.State, c rune)      { format(rr, f, c) }
func (rr *KEY) Format(f fmt.State, c rune)        { format(rr, f, c) }
func (rr *DNSKEY) Format(f fmt.State, c rune)     { format(rr, f, c) }
func (rr *DS) Format(f fmt.State, c rune)         { format(rr, f, c) }
func (rr *EUI48) Format(f fmt.State, c rune)      { format(rr, f, c) }
func (rr *EUI64) Format(f fmt.State, c rune)      { format(rr, f, c) }
func (rr *GID) Format(f fmt.State, c rune)        { format(rr, f, c) }
func (rr *GPOS) Format(f fmt.State, c rune)       { format(rr, f, c) }
func (rr *EID) Format(f fmt.State, c rune)        { format(rr, f, c) }
func (rr *HINFO) Format(f fmt.State, c rune)      { format(rr, f, c) }
func (rr *HIP) Format(f fmt.State, c rune)        { format(rr, f, c) }
func (rr *KX) Format(f fmt.State, c rune)         { format(rr, f, c) }
func (rr *L32) Format(f fmt.State, c rune)        { format(rr, f, c) }
func (rr *L64) Format(f fmt.State, c rune)        { format(rr, f, c) }
func (rr *LOC) Format(f fmt.State, c rune)        { format(rr, f, c) }
func (rr *LP) Format(f fmt.State, c rune)         { format(rr, f, c) }
func (rr *MB) Format(f fmt.State, c rune)         { format(rr, f, c) }
func (rr *MD) Format(f fmt.State, c rune)         { format(rr, f, c) }
func (rr *MF) Format(f fmt.State, c rune)         { format(rr, f, c) }
func (rr *MG) Format(f fmt.State, c rune)         { format(rr, f, c) }
func (rr *MINFO) Format(f fmt.State, c rune)      { format(rr, f, c) }
func (rr *MR) Format(f fmt.State, c rune)         { format(rr, f, c) }
func (rr *MX) Format(f fmt.State, c rune)         { format(rr, f, c) }
func (rr *NAPTR) Format(f fmt.State, c rune)      { format(rr, f, c) }
func (rr *NID) Format(f fmt.State, c rune)        { format(rr, f, c) }
func (rr *NINFO) Format(f fmt.State, c rune)      { format(rr, f, c) }
func (rr *NIMLOC) Format(f fmt.State, c rune)     { format(rr, f, c) }
func (rr *NS) Format(f fmt.State, c rune)         { format(rr, f, c) }
func (rr *NSAP) Format(f fmt.State, c rune)       { format(rr, f, c) }
func (rr *NSAPPTR) Format(f fmt.State, c rune)    { format(rr, f, c) }
func (rr *NSEC3) Format(f fmt.State, c rune)      { format(rr, f, c) }
func (rr *NSEC3PARAM) Format(f fmt.State, c rune) { format(rr, f, c) }
func (rr *NSEC) Format(f fmt.State, c rune)       { format(rr, f, c) }
func (rr *OPENPGPKEY) Format(f fmt.State, c rune) { format(rr, f, c) }
func (rr *OPT) Format(f fmt.State, c rune)        { format(rr, f, c) }
func (rr *PTR) Format(f fmt.State, c rune)        { format(rr, f, c) }
func (rr *RKEY) Format(f fmt.State, c rune)       { format(rr, f, c) }
func (rr *RP) Format(f fmt.State, c rune)         { format(rr, f, c) }
func (rr *PX) Format(f fmt.State, c rune)         { format(rr, f, c) }
func (rr *SIG) Format(f fmt.State, c rune)        { format(rr, f, c) }
func (rr *RRSIG) Format(f fmt.State, c rune)      { format(rr, f, c) }
func (rr *RT) Format(f fmt.State, c rune)         { format(rr, f, c) }
func (rr *SOA) Format(f fmt.State, c rune)        { format(rr, f, c) }
func (rr *SPF) Format(f fmt.State, c rune)        { format(rr, f, c) }
func (rr *SRV) Format(f fmt.State, c rune)        { format(rr, f, c) }
func (rr *SSHFP) Format(f fmt.State, c rune)      { format(rr, f, c) }
func (rr *TA) Format(f fmt.State, c rune)         { format(rr, f, c) }
func (rr *TALINK) Format(f fmt.State, c rune)     { format(rr, f, c) }
func (rr *TKEY) Format(f fmt.State, c rune)       { format(rr, f, c) }
func (rr *TLSA) Format(f fmt.State, c rune)       { format(rr, f, c) }
func (rr *TSIG) Format(f fmt.State, c rune)       { format(rr, f, c) }
func (rr *TXT) Format(f fmt.State, c rune)        { format(rr, f, c) }
func (rr *UID) Format(f fmt.State, c rune)        { format(rr, f, c) }
func (rr *UINFO) Format(f fmt.State, c rune)      { format(rr, f, c) }
func (rr *URI) Format(f fmt.State, c rune)        { format(rr, f, c) }
func (rr *WKS) Format(f fmt.State, c rune)        { format(rr, f, c) }
func (rr *X25) Format(f fmt.State, c rune)        { format(rr, f, c) }
