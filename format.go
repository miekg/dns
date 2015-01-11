// FORMAT
//
// The dns package implements String() for all RR types, but sometimes you will
// need more flexibility. Here we define an extra set of formatting verbs that
// can be used in the formatted I/O package fmt.
//
// Printing
//
// The verbs:
//
// Generic parts of RRs:
//
//	%N	the owner name of the RR
//	%C	the class: IN, CH, CLASS15, etc.
//	%D	the TTL in seconds
//	%Y	the type: MX, A, etc.
//
// The rdata of each RR differs, we allow each field to be accessed as a string with
// the Field function.
//
package dns

import (
	"fmt"
	"reflect"
	"strconv"
)

// Field returns the rdata field i as a string. Fields are indexed starting from 1.
// Non existing fields will return the empty string.
func Field(r RR, i int) string {
	if i == 0 {
		return ""
	}
	d := reflect.ValueOf(r).Elem().Field(i)
	switch d.Kind() {
	case reflect.String:
		return d.String()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(d.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(d.Uint(), 10)
		// more to be added
	}
	return ""
}

// NumField returns the number of rdata fields r has.
func NumField(r RR) int {
	return reflect.ValueOf(r).Elem().NumField() - 1 // Remove RR_Header
}

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
	case 's':
		f.Write([]byte(r.String()))
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
	case 's':
		f.Write([]byte(h.String()))
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
