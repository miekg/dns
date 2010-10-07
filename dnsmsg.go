// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS packet assembly.  See RFC 1035.
//
// This is intended to support name resolution during net.Dial.
// It doesn't have to be blazing fast.
//
// Rather than write the usual handful of routines to pack and
// unpack every message that can appear on the wire, we use
// reflection to write a generic pack/unpack for structs and then
// use it.  Thus, if in the future we need to define new message
// structs, no new pack/unpack/printing code needs to be written.
//
// The first half of this file defines the DNS message formats.
// The second half implements the conversion to and from wire format.
// A few of the structure elements have string tags to aid the
// generic pack/unpack routines.
//
// TODO(miekg):

package dns

import (
	"fmt"
	"os"
	"reflect"
	"net"
	"strconv"
	"encoding/base64"
	"encoding/hex"
)

// Packing and unpacking.
//
// All the packers and unpackers take a (msg []byte, off int)
// and return (off1 int, ok bool).  If they return ok==false, they
// also return off1==len(msg), so that the next unpacker will
// also fail.  This lets us avoid checks of ok until the end of a
// packing sequence.

// Map of strings for each RR wire type.
var class_str = map[uint16]string{
	ClassINET:   "IN",
	ClassCSNET:  "CS",
	ClassCHAOS:  "CH",
	ClassHESIOD: "HS",
	ClassANY:    "ANY",
}

// Map of strings for opcodes.
var opcode_str = map[int]string{
	0: "QUERY",
}

// Map of strings for rcode
var rcode_str = map[int]string{
	0: "NOERROR",


	3: "NXDOMAIN",
}

// Pack a domain name s into msg[off:].
// Domain names are a sequence of counted strings
// split at the dots.  They end with a zero-length string.
func packDomainName(s string, msg []byte, off int) (off1 int, ok bool) {
	// Add trailing dot to canonicalize name.
	if n := len(s); n == 0 || s[n-1] != '.' {
		s += "."
	}

	// Each dot ends a segment of the name.
	// We trade each dot byte for a length byte.
	// There is also a trailing zero.
	// Check that we have all the space we need.
	tot := len(s) + 1
	if off+tot > len(msg) {
		return len(msg), false
	}

	// Emit sequence of counted strings, chopping at dots.
	begin := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			if i-begin >= 1<<6 { // top two bits of length must be clear
				return len(msg), false
			}
			msg[off] = byte(i - begin)
			off++
			for j := begin; j < i; j++ {
				msg[off] = s[j]
				off++
			}
			begin = i + 1
		}
	}
	msg[off] = 0
	off++
	return off, true
}

// Unpack a domain name.
// In addition to the simple sequences of counted strings above,
// domain names are allowed to refer to strings elsewhere in the
// packet, to avoid repeating common suffixes when returning
// many entries in a single domain.  The pointers are marked
// by a length byte with the top two bits set.  Ignoring those
// two bits, that byte and the next give a 14 bit offset from msg[0]
// where we should pick up the trail.
// Note that if we jump elsewhere in the packet,
// we return off1 == the offset after the first pointer we found,
// which is where the next record will start.
// In theory, the pointers are only allowed to jump backward.
// We let them jump anywhere and stop jumping after a while.
func unpackDomainName(msg []byte, off int) (s string, off1 int, ok bool) {
	s = ""
	ptr := 0 // number of pointers followed
Loop:
	for {
		if off >= len(msg) {
			return "", len(msg), false
		}
		c := int(msg[off])
		off++
		switch c & 0xC0 {
		case 0x00:
			if c == 0x00 {
				// end of name
				break Loop
			}
			// literal string
			if off+c > len(msg) {
				return "", len(msg), false
			}
			s += string(msg[off:off+c]) + "."
			off += c
		case 0xC0:
			// pointer to somewhere else in msg.
			// remember location after first ptr,
			// since that's how many bytes we consumed.
			// also, don't follow too many pointers --
			// maybe there's a loop.
			if off >= len(msg) {
				return "", len(msg), false
			}
			c1 := msg[off]
			off++
			if ptr == 0 {
				off1 = off
			}
			if ptr++; ptr > 10 {
				return "", len(msg), false
			}
			off = (c^0xC0)<<8 | int(c1)
		default:
			// 0x80 and 0x40 are reserved
			return "", len(msg), false
		}
	}
	if ptr == 0 {
		off1 = off
	}
	return s, off1, true
}

// TODO(rsc): Move into generic library?
// Pack a reflect.StructValue into msg.  Struct members can only be uint8, uint16, uint32, string,
// slices and other (often anonymous) structs.
func packStructValue(val *reflect.StructValue, msg []byte, off int) (off1 int, ok bool) {
	for i := 0; i < val.NumField(); i++ {
		f := val.Type().(*reflect.StructType).Field(i)
		switch fv := val.Field(i).(type) {
		default:
		BadType:
			fmt.Fprintf(os.Stderr, "net: dns: unknown packing type %v", f.Type)
			return len(msg), false
		case *reflect.SliceValue:
			switch f.Tag {
			default:
				fmt.Fprintf(os.Stderr, "net: dns: unknown IP tag %v", f.Tag)
				return len(msg), false
			case "ipv4":
				if fv.Len() > net.IPv4len || off+fv.Len() > len(msg) {
					return len(msg), false
				}
				msg[off]   = byte(fv.Elem(0).(*reflect.UintValue).Get())
				msg[off+1] = byte(fv.Elem(1).(*reflect.UintValue).Get())
				msg[off+2] = byte(fv.Elem(2).(*reflect.UintValue).Get())
				msg[off+3] = byte(fv.Elem(3).(*reflect.UintValue).Get())
				off += net.IPv4len
			case "ipv6":
				if fv.Len() > net.IPv6len || off+fv.Len() > len(msg) {
					return len(msg), false
				}
				for j:=0; j<net.IPv6len; j++ {
					msg[off] = byte(fv.Elem(j).(*reflect.UintValue).Get())
					off++
				}
			}
		case *reflect.StructValue:
			off, ok = packStructValue(fv, msg, off)
		case *reflect.UintValue:
			i := fv.Get()
			switch fv.Type().Kind() {
			default:
				goto BadType
			case reflect.Uint8:
				if off+1 > len(msg) {
					return len(msg), false
				}
				msg[off] = byte(i)
				off++
			case reflect.Uint16:
				if off+2 > len(msg) {
					return len(msg), false
				}
				msg[off] = byte(i >> 8)
				msg[off+1] = byte(i)
				off += 2
			case reflect.Uint32:
				if off+4 > len(msg) {
					return len(msg), false
				}
				msg[off] = byte(i >> 24)
				msg[off+1] = byte(i >> 16)
				msg[off+2] = byte(i >> 8)
				msg[off+3] = byte(i)
				off += 4
			}
		case *reflect.StringValue:
			// There are multiple string encodings.
			// The tag distinguishes ordinary strings from domain names.
			s := fv.Get()
			switch f.Tag {
			default:
				return len(msg), false
			case "base64":
				//TODO
			case "domain-name":
				off, ok = packDomainName(s, msg, off)
				if !ok {
					return len(msg), false
				}
			case "":
				// Counted string: 1 byte length.
				if len(s) > 255 || off+1+len(s) > len(msg) {
					return len(msg), false
				}
				msg[off] = byte(len(s))
				off++
				for i := 0; i < len(s); i++ {
					msg[off+i] = s[i]
				}
				off += len(s)
			}
		}
	}
	return off, true
}

func structValue(any interface{}) *reflect.StructValue {
	return reflect.NewValue(any).(*reflect.PtrValue).Elem().(*reflect.StructValue)
}

func packStruct(any interface{}, msg []byte, off int) (off1 int, ok bool) {
	off, ok = packStructValue(structValue(any), msg, off)
	return off, ok
}

// Unpack a reflect.StructValue from msg.
// Same restrictions as packStructValue.
func unpackStructValue(val *reflect.StructValue, msg []byte, off int) (off1 int, ok bool) {
	for i := 0; i < val.NumField(); i++ {
		f := val.Type().(*reflect.StructType).Field(i)
		switch fv := val.Field(i).(type) {
		default:
		BadType:
			fmt.Fprintf(os.Stderr, "net: dns: unknown packing type %v", f.Type)
			return len(msg), false
		case *reflect.SliceValue:
			switch f.Tag {
			default:
				fmt.Fprintf(os.Stderr, "net: dns: unknown IP tag %v", f.Tag)
				return len(msg), false
			case "ipv4":
				if off+net.IPv4len > len(msg) {
					return len(msg), false
				}
				b := net.IPv4(msg[off], msg[off+1], msg[off+2], msg[off+3])
				fv.Set(reflect.NewValue(b).(*reflect.SliceValue))
				off += net.IPv4len
			case "ipv6":
				if off+net.IPv6len > len(msg) {
					return len(msg), false
				}
				p := make(net.IP, net.IPv6len)
				copy(p, msg[off:off+net.IPv6len])
				b := net.IP(p)
				fv.Set(reflect.NewValue(b).(*reflect.SliceValue))
				off += net.IPv6len
			}
		case *reflect.StructValue:
			off, ok = unpackStructValue(fv, msg, off)
		case *reflect.UintValue:
			switch fv.Type().Kind() {
			default:
				goto BadType
			case reflect.Uint8:
				if off+1 > len(msg) {
					return len(msg), false
				}
				i := uint8(msg[off])
				fv.Set(uint64(i))
				off++
			case reflect.Uint16:
				if off+2 > len(msg) {
					return len(msg), false
				}
				i := uint16(msg[off])<<8 | uint16(msg[off+1])
				fv.Set(uint64(i))
				off += 2
			case reflect.Uint32:
				if off+4 > len(msg) {
					return len(msg), false
				}
				i := uint32(msg[off])<<24 | uint32(msg[off+1])<<16 | uint32(msg[off+2])<<8 | uint32(msg[off+3])
				fv.Set(uint64(i))
				off += 4
			}
		case *reflect.StringValue:
			var s string
			switch f.Tag {
			default:
				fmt.Fprintf(os.Stderr, "net: dns: unknown string tag %v", f.Tag)
				return len(msg), false
			case "hex":
				// Rest of the RR is hex encoded
				rdlength := int(val.FieldByName("Hdr").(*reflect.StructValue).FieldByName("Rdlength").(*reflect.UintValue).Get())
				var consumed int
				switch val.Type().Name() {
				case "RR_DS":
					consumed = 4 // KeyTag(2) + Algorithm(1) + DigestType(1)
				default:
					consumed = 0 // TODO
				}
				s = hex.EncodeToString(msg[off:off+rdlength-consumed])
				off += rdlength-consumed
			case "base64":
				// Rest of the RR is base64 encoded value
				rdlength := int(val.FieldByName("Hdr").(*reflect.StructValue).FieldByName("Rdlength").(*reflect.UintValue).Get())
				// Need to know how much of rdlength is already consumed
				var consumed int
				// Can't I figure out via reflect how many bytes there are already consumed??
				switch val.Type().Name() {
				case "RR_DNSKEY":
					consumed = 4 // Flags(2) + Protocol(1) + Algorithm(1)
				case "RR_DS":
					consumed = 4 // KeyTag(2) + Algorithm(1) + DigestType(1)
				default:
					consumed = 0 // TODO
				}
				b64 := make([]byte, base64.StdEncoding.EncodedLen(len(msg[off:off+rdlength-consumed])))
				base64.StdEncoding.Encode(b64, msg[off:off+rdlength-consumed])
				s = string(b64)
				off += rdlength-consumed
			case "domain-name":
				s, off, ok = unpackDomainName(msg, off)
				if !ok {
					return len(msg), false
				}
			case "":
				if off >= len(msg) || off+1+int(msg[off]) > len(msg) {
					return len(msg), false
				}
				n := int(msg[off])
				off++
				b := make([]byte, n)
				for i := 0; i < n; i++ {
					b[i] = msg[off+i]
				}
				off += n
				s = string(b)
			}
			fv.Set(s)
		}
	}
	return off, true
}

func unpackStruct(any interface{}, msg []byte, off int) (off1 int, ok bool) {
	off, ok = unpackStructValue(structValue(any), msg, off)
	return off, ok
}

// Generic struct printer.
// Doesn't care about the string tag "domain-name",
func printStructValue(val *reflect.StructValue) string {
	s := "{"
	for i := 0; i < val.NumField(); i++ {
		if i > 0 {
			s += ", "
		}
		f := val.Type().(*reflect.StructType).Field(i)
		if !f.Anonymous {
			s += f.Name + "="
		}
		fval := val.Field(i)
		if fv, ok := fval.(*reflect.StructValue); ok {
			s += printStructValue(fv)
		} else {
			s += fmt.Sprint(fval.Interface())
		}
	}
	s += "}"
	return s
}

func PrintStruct(any interface{}) string { return printStructValue(structValue(any)) }

// Resource record packer.
func packRR(rr RR, msg []byte, off int) (off2 int, ok bool) {
	var off1 int
	// pack twice, once to find end of header
	// and again to find end of packet.
	// a bit inefficient but this doesn't need to be fast.
	// off1 is end of header
	// off2 is end of rr
	off1, ok = packStruct(rr.Header(), msg, off)
	off2, ok = packStruct(rr, msg, off)
	if !ok {
		return len(msg), false
	}
	// pack a third time; redo header with correct data length
	rr.Header().Rdlength = uint16(off2 - off1)
	packStruct(rr.Header(), msg, off)
	return off2, true
}

// Resource record unpacker.
func unpackRR(msg []byte, off int) (rr RR, off1 int, ok bool) {
	// unpack just the header, to find the rr type and length
	var h RR_Header
	off0 := off
	if off, ok = unpackStruct(&h, msg, off); !ok {
		return nil, len(msg), false
	}
	end := off + int(h.Rdlength)

	// make an rr of that type and re-unpack.
	// again inefficient but doesn't need to be fast.
	mk, known := rr_mk[int(h.Rrtype)]
	if !known {
		return &h, end, true
	}
	rr = mk()
	off, ok = unpackStruct(rr, msg, off0)
	if off != end {
		return &h, end, true
	}
	return rr, off, ok
}

// Usable representation of a DNS packet.

// A manually-unpacked version of (id, bits).
// This is in its own struct for easy printing.
type MsgHdr struct {
	id                  uint16
	response            bool
	opcode              int
	authoritative       bool
	truncated           bool
	recursion_desired   bool
	recursion_available bool
	rcode               int
}

//;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 48404
//;; flags: qr aa rd ra;
func (h *MsgHdr) String() string {
	if h == nil {
		return "<nil> MsgHdr"
	}

	s := ";; ->>HEADER<<- opcode: " + opcode_str[h.opcode]
	s += ", status: " + rcode_str[h.rcode]
	s += ", id: " + strconv.Itoa(int(h.id)) + "\n"

	s += ";; flags: "
	if h.authoritative {
		s += "aa "
	}
	if h.truncated {
		s += "tc "
	}
	if h.recursion_desired {
		s += "rd "
	}
	if h.recursion_available {
		s += "ra "
	}
	s += ";"
	return s
}

type Msg struct {
	MsgHdr
	Question []Question
	Edns     []Edns
	Answer   []RR
	Ns       []RR
	Extra    []RR
}


func (dns *Msg) Pack() (msg []byte, ok bool) {
	var dh Header

	// Convert convenient Msg into wire-like Header.
	dh.Id = dns.id
	dh.Bits = uint16(dns.opcode)<<11 | uint16(dns.rcode)
	if dns.recursion_available {
		dh.Bits |= _RA
	}
	if dns.recursion_desired {
		dh.Bits |= _RD
	}
	if dns.truncated {
		dh.Bits |= _TC
	}
	if dns.authoritative {
		dh.Bits |= _AA
	}
	if dns.response {
		dh.Bits |= _QR
	}

	// Prepare variable sized arrays.
	question := dns.Question
	answer := dns.Answer
	ns := dns.Ns
	extra := dns.Extra

	dh.Qdcount = uint16(len(question))
	dh.Ancount = uint16(len(answer))
	dh.Nscount = uint16(len(ns))
	dh.Arcount = uint16(len(extra))

	// Could work harder to calculate message size,
	// but this is far more than we need and not
	// big enough to hurt the allocator.
	msg = make([]byte, 2000)

	// Pack it in: header and then the pieces.
	off := 0
	off, ok = packStruct(&dh, msg, off)
	for i := 0; i < len(question); i++ {
		off, ok = packStruct(&question[i], msg, off)
	}
	for i := 0; i < len(answer); i++ {
		off, ok = packRR(answer[i], msg, off)
	}
	for i := 0; i < len(ns); i++ {
		off, ok = packRR(ns[i], msg, off)
	}
	for i := 0; i < len(extra); i++ {
		off, ok = packRR(extra[i], msg, off)
	}
	if !ok {
		return nil, false
	}
	return msg[0:off], true
}

func (dns *Msg) Unpack(msg []byte) bool {
	// Header.
	var dh Header
	off := 0
	var ok bool
	if off, ok = unpackStruct(&dh, msg, off); !ok {
		return false
	}
	dns.id = dh.Id
	dns.response = (dh.Bits & _QR) != 0
	dns.opcode = int(dh.Bits>>11) & 0xF
	dns.authoritative = (dh.Bits & _AA) != 0
	dns.truncated = (dh.Bits & _TC) != 0
	dns.recursion_desired = (dh.Bits & _RD) != 0
	dns.recursion_available = (dh.Bits & _RA) != 0
	dns.rcode = int(dh.Bits & 0xF)

	// Arrays.
	dns.Question = make([]Question, dh.Qdcount)
	dns.Answer = make([]RR, dh.Ancount)
	dns.Ns = make([]RR, dh.Nscount)
	dns.Extra = make([]RR, dh.Arcount)

	for i := 0; i < len(dns.Question); i++ {
		off, ok = unpackStruct(&dns.Question[i], msg, off)
	}
	for i := 0; i < len(dns.Answer); i++ {
		dns.Answer[i], off, ok = unpackRR(msg, off)
	}
	for i := 0; i < len(dns.Ns); i++ {
		dns.Ns[i], off, ok = unpackRR(msg, off)
	}
	for i := 0; i < len(dns.Extra); i++ {
		dns.Extra[i], off, ok = unpackRR(msg, off)
	}
	if !ok {
		return false
	}
	if off != len(msg) {
		println("extra bytes in dns packet", off, "<", len(msg))
	}
	return true
}

func (dns *Msg) String() string {
	if dns == nil {
		return "<nil> MsgHdr"
	}
	s := dns.MsgHdr.String() + " "
	s += "QUERY: " + strconv.Itoa(len(dns.Question)) + ", "
	s += "ANSWER: " + strconv.Itoa(len(dns.Answer)) + ", "
	s += "AUTHORITY: " + strconv.Itoa(len(dns.Ns)) + ", "
	s += "ADDITIONAL: " + strconv.Itoa(len(dns.Extra)) + "\n"
	if len(dns.Question) > 0 {
		s += "\n;; QUESTION SECTION:\n"
		for i := 0; i < len(dns.Question); i++ {
			s += dns.Question[i].String() + "\n"
		}
	}
	if len(dns.Answer) > 0 {
		s += "\n;; ANSWER SECTION:\n"
		for i := 0; i < len(dns.Answer); i++ {
			s += dns.Answer[i].String() + "\n"
		}
	}
	if len(dns.Ns) > 0 {
		s += "\n;; AUTHORITY SECTION:\n"
		for i := 0; i < len(dns.Ns); i++ {
			s += dns.Ns[i].String() + "\n"
		}
	}
	if len(dns.Extra) > 0 {
		s += "\n;; ADDITIONAL SECTION:\n"
		for i := 0; i < len(dns.Extra); i++ {
			s += dns.Extra[i].String() + "\n"
		}
	}
	return s
}
