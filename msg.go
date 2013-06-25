// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Extensions of the original work are copyright (c) 2011 Miek Gieben

// DNS packet assembly, see RFC 1035. Converting from - Unpack() -
// and to - Pack() - wire format.
// All the packers and unpackers take a (msg []byte, off int)
// and return (off1 int, ok bool).  If they return ok==false, they
// also return off1==len(msg), so that the next unpacker will
// also fail.  This lets us avoid checks of ok until the end of a
// packing sequence.

package dns

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"reflect"
	"strconv"
)

const maxCompressionOffset = 2 << 13 // We have 14 bits for the compression pointer

var (
	ErrFqdn      error = &Error{err: "domain must be fully qualified"}
	ErrId        error = &Error{err: "id mismatch"}
	ErrRdata     error = &Error{err: "bad rdata"}
	ErrBuf       error = &Error{err: "buffer size too small"}
	ErrShortRead error = &Error{err: "short read"}
	ErrConn      error = &Error{err: "conn holds both UDP and TCP connection"}
	ErrConnEmpty error = &Error{err: "conn has no connection"}
	ErrServ      error = &Error{err: "no servers could be reached"}
	ErrKey       error = &Error{err: "bad key"}
	ErrPrivKey   error = &Error{err: "bad private key"}
	ErrKeySize   error = &Error{err: "bad key size"}
	ErrKeyAlg    error = &Error{err: "bad key algorithm"}
	ErrAlg       error = &Error{err: "bad algorithm"}
	ErrTime      error = &Error{err: "bad time"}
	ErrNoSig     error = &Error{err: "no signature found"}
	ErrSig       error = &Error{err: "bad signature"}
	ErrSecret    error = &Error{err: "no secrets defined"}
	ErrSigGen    error = &Error{err: "bad signature generation"}
	ErrAuth      error = &Error{err: "bad authentication"}
	ErrSoa       error = &Error{err: "no SOA"}
	ErrRRset     error = &Error{err: "bad rrset"}

	maxId = big.NewInt(0xFFFF)
)

// A manually-unpacked version of (id, bits).
// This is in its own struct for easy printing.
type MsgHdr struct {
	Id                 uint16
	Response           bool
	Opcode             int
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	Zero               bool
	AuthenticatedData  bool
	CheckingDisabled   bool
	Rcode              int
}

// The layout of a DNS message.
type Msg struct {
	MsgHdr
	Compress bool       `json:"-"` // If true, the message will be compressed when converted to wire format.
	Question []Question // Holds the RR(s) of the question section.
	Answer   []RR       // Holds the RR(s) of the answer section.
	Ns       []RR       // Holds the RR(s) of the authority section.
	Extra    []RR       // Holds the RR(s) of the additional section.
}

// Map of strings for each RR wire type.
var TypeToString = map[uint16]string{
	TypeCNAME:      "CNAME",
	TypeHINFO:      "HINFO",
	TypeTLSA:       "TLSA",
	TypeMB:         "MB",
	TypeMG:         "MG",
	TypeRP:         "RP",
	TypeMD:         "MD",
	TypeMF:         "MF",
	TypeMINFO:      "MINFO",
	TypeMR:         "MR",
	TypeMX:         "MX",
	TypeWKS:        "WKS",
	TypeNS:         "NS",
	TypeNULL:       "NULL",
	TypeAFSDB:      "AFSDB",
	TypeX25:        "X25",
	TypeISDN:       "ISDN",
	TypePTR:        "PTR",
	TypeRT:         "RT",
	TypeSOA:        "SOA",
	TypeTXT:        "TXT",
	TypeSRV:        "SRV",
	TypeATMA:       "ATMA",
	TypeNAPTR:      "NAPTR",
	TypeKX:         "KX",
	TypeCERT:       "CERT",
	TypeDNAME:      "DNAME",
	TypeA:          "A",
	TypeAAAA:       "AAAA",
	TypeLOC:        "LOC",
	TypeOPT:        "OPT",
	TypeDS:         "DS",
	TypeDHCID:      "DHCID",
	TypeHIP:        "HIP",
	TypeNINFO:      "NINFO",
	TypeRKEY:       "RKEY",
	TypeCDS:        "CDS",
	TypeCAA:        "CAA",
	TypeIPSECKEY:   "IPSECKEY",
	TypeSSHFP:      "SSHFP",
	TypeRRSIG:      "RRSIG",
	TypeNSEC:       "NSEC",
	TypeDNSKEY:     "DNSKEY",
	TypeNSEC3:      "NSEC3",
	TypeNSEC3PARAM: "NSEC3PARAM",
	TypeTALINK:     "TALINK",
	TypeSPF:        "SPF",
	TypeNID:        "NID",
	TypeL32:        "L32",
	TypeL64:        "L64",
	TypeLP:         "LP",
	TypeUINFO:      "UINFO",
	TypeUID:        "UID",
	TypeGID:        "GID",
	TypeUNSPEC:     "UNSPEC",
	TypeEUI48:      "EUI48",
	TypeEUI64:      "EUI64",
	TypeTKEY:       "TKEY", // Meta RR
	TypeTSIG:       "TSIG", // Meta RR
	TypeAXFR:       "AXFR", // Meta RR
	TypeIXFR:       "IXFR", // Meta RR
	TypeANY:        "ANY",  // Meta RR
	TypeURI:        "URI",
	TypeTA:         "TA",
	TypeDLV:        "DLV",
}

// Reverse, needed for string parsing.
var StringToType = reverseInt16(TypeToString)
var StringToClass = reverseInt16(ClassToString)

// Map of opcodes strings.
var StringToOpcode = reverseInt(OpcodeToString)

// Map of rcodes strings.
var StringToRcode = reverseInt(RcodeToString)

// Map of strings for each CLASS wire type.
var ClassToString = map[uint16]string{
	ClassINET:   "IN",
	ClassCSNET:  "CS",
	ClassCHAOS:  "CH",
	ClassHESIOD: "HS",
	ClassNONE:   "NONE",
	ClassANY:    "ANY",
}

// Map of strings for opcodes.
var OpcodeToString = map[int]string{
	OpcodeQuery:  "QUERY",
	OpcodeIQuery: "IQUERY",
	OpcodeStatus: "STATUS",
	OpcodeNotify: "NOTIFY",
	OpcodeUpdate: "UPDATE",
}

// Map of strings for rcodes.
var RcodeToString = map[int]string{
	RcodeSuccess:        "NOERROR",
	RcodeFormatError:    "FORMERR",
	RcodeServerFailure:  "SERVFAIL",
	RcodeNameError:      "NXDOMAIN",
	RcodeNotImplemented: "NOTIMPL",
	RcodeRefused:        "REFUSED",
	RcodeYXDomain:       "YXDOMAIN", // From RFC 2136
	RcodeYXRrset:        "YXRRSET",
	RcodeNXRrset:        "NXRRSET",
	RcodeNotAuth:        "NOTAUTH",
	RcodeNotZone:        "NOTZONE",
	RcodeBadSig:         "BADSIG", // Also known as RcodeBadVers, see RFC 6891
	//	RcodeBadVers:        "BADVERS",
	RcodeBadKey:   "BADKEY",
	RcodeBadTime:  "BADTIME",
	RcodeBadMode:  "BADMODE",
	RcodeBadName:  "BADNAME",
	RcodeBadAlg:   "BADALG",
	RcodeBadTrunc: "BADTRUNC",
}

// Rather than write the usual handful of routines to pack and
// unpack every message that can appear on the wire, we use
// reflection to write a generic pack/unpack for structs and then
// use it. Thus, if in the future we need to define new message
// structs, no new pack/unpack/printing code needs to be written.

// Domain names are a sequence of counted strings
// split at the dots. They end with a zero-length string.

// PackDomainName packs a domain name s into msg[off:].
// If compression is wanted compress must be true and the compression
// map needs to hold a mapping between domain names and offsets
// pointing into msg[].
func PackDomainName(s string, msg []byte, off int, compression map[string]int, compress bool) (off1 int, err error) {
	lenmsg := len(msg)
	ls := len(s)
	// If not fully qualified, error out
	if ls == 0 || s[ls-1] != '.' {
		return lenmsg, ErrFqdn
	}
	// Each dot ends a segment of the name.
	// We trade each dot byte for a length byte.
	// Except for escaped dots (\.), which are normal dots.
	// There is also a trailing zero.

	// Compression
	nameoffset := -1
	pointer := -1
	// Emit sequence of counted strings, chopping at dots.
	begin := 0
	bs := []byte(s)
	for i := 0; i < ls; i++ {
		if bs[i] == '\\' {
			for j := i; j < ls-1; j++ {
				bs[j] = bs[j+1]
			}
			ls--
			if off+1 > lenmsg {
				return lenmsg, ErrBuf
			}
			// check for \DDD
			if i+2 < ls && bs[i] >= '0' && bs[i] <= '9' &&
				bs[i+1] >= '0' && bs[i+1] <= '9' &&
				bs[i+2] >= '0' && bs[i+2] <= '9' {
				bs[i] = byte((bs[i]-'0')*100 + (bs[i+1]-'0')*10 + (bs[i+2] - '0'))
				for j := i + 1; j < ls-2; j++ {
					bs[j] = bs[j+2]
				}
				ls -= 2
			}
			continue
		}

		if bs[i] == '.' {
			if i-begin >= 1<<6 { // top two bits of length must be clear
				return lenmsg, ErrRdata
			}
			// off can already (we're in a loop) be bigger than len(msg)
			// this happens when a name isn't fully qualified
			if off+1 > lenmsg {
				return lenmsg, ErrBuf
			}
			msg[off] = byte(i - begin)
			offset := off
			off++
			for j := begin; j < i; j++ {
				if off+1 > lenmsg {
					return lenmsg, ErrBuf
				}
				msg[off] = bs[j]
				off++
			}
			// Dont try to compress '.'
			if compression != nil && string(bs[begin:]) != "." {
				if p, ok := compression[string(bs[begin:])]; !ok {
					// Only offsets smaller than this can be used.
					if offset < maxCompressionOffset {
						compression[string(bs[begin:])] = offset
					}
				} else {
					// The first hit is the longest matching dname
					// keep the pointer offset we get back and store
					// the offset of the current name, because that's
					// where we need to insert the pointer later

					// If compress is true, we're  allowed to compress this dname
					if pointer == -1 && compress {
						pointer = p         // Where to point to
						nameoffset = offset // Where to point from
						break
					}
				}
			}
			begin = i + 1
		}
	}
	// Root label is special
	if len(bs) == 1 && bs[0] == '.' {
		return off, nil
	}
	// If we did compression and we find something at the pointer here
	if pointer != -1 {
		// We have two bytes (14 bits) to put the pointer in
		msg[nameoffset], msg[nameoffset+1] = packUint16(uint16(pointer ^ 0xC000))
		off = nameoffset + 1
		goto End
	}
	msg[off] = 0
End:
	off++
	return off, nil
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

// UnpackDomainName unpacks a domain name into a string.
func UnpackDomainName(msg []byte, off int) (s string, off1 int, err error) {
	s = ""
	lenmsg := len(msg)
	ptr := 0 // number of pointers followed
Loop:
	for {
		if off >= lenmsg {
			return "", lenmsg, ErrBuf
		}
		c := int(msg[off])
		off++
		switch c & 0xC0 {
		case 0x00:
			if c == 0x00 {
				// end of name
				if s == "" {
					return ".", off, nil
				}
				break Loop
			}
			// literal string
			if off+c > lenmsg {
				return "", lenmsg, ErrBuf
			}
			for j := off; j < off+c; j++ {
				switch {
				case msg[j] == '.': // literal dots
					s += "\\."
				case msg[j] < 32: // unprintable use \DDD
					fallthrough
				case msg[j] >= 127:
					s += fmt.Sprintf("\\%03d", msg[j])
				default:
					s += string(msg[j])
				}
			}
			s += "."
			off += c
		case 0xC0:
			// pointer to somewhere else in msg.
			// remember location after first ptr,
			// since that's how many bytes we consumed.
			// also, don't follow too many pointers --
			// maybe there's a loop.
			if off >= lenmsg {
				return "", lenmsg, ErrBuf
			}
			c1 := msg[off]
			off++
			if ptr == 0 {
				off1 = off
			}
			if ptr++; ptr > 10 {
				return "", lenmsg, &Error{err: "too many compression pointers"}
			}
			off = (c^0xC0)<<8 | int(c1)
		default:
			// 0x80 and 0x40 are reserved
			return "", lenmsg, ErrRdata
		}
	}
	if ptr == 0 {
		off1 = off
	}
	return s, off1, nil
}

// Pack a reflect.StructValue into msg.  Struct members can only be uint8, uint16, uint32, string,
// slices and other (often anonymous) structs.
func packStructValue(val reflect.Value, msg []byte, off int, compression map[string]int, compress bool) (off1 int, err error) {
	lenmsg := len(msg)
	for i := 0; i < val.NumField(); i++ {
		switch fv := val.Field(i); fv.Kind() {
		default:
			return lenmsg, &Error{err: "bad kind packing"}
		case reflect.Slice:
			switch val.Type().Field(i).Tag {
			default:
				return lenmsg, &Error{"bad tag packing slice: " + val.Type().Field(i).Tag.Get("dns")}
			case `dns:"domain-name"`:
				for j := 0; j < val.Field(i).Len(); j++ {
					element := val.Field(i).Index(j).String()
					off, err = PackDomainName(element, msg, off, compression, false && compress)
					if err != nil {
						return lenmsg, err
					}
				}
			case `dns:"txt"`:
				for j := 0; j < val.Field(i).Len(); j++ {
					element := val.Field(i).Index(j).String()
					// Counted string: 1 byte length.
					if len(element) > 255 || off+1+len(element) > lenmsg {
						return lenmsg, &Error{err: "overflow packing txt"}
					}
					msg[off] = byte(len(element))
					off++
					for i := 0; i < len(element); i++ {
						msg[off+i] = element[i]
					}
					off += len(element)
				}
			case `dns:"opt"`: // edns
				for j := 0; j < val.Field(i).Len(); j++ {
					element := val.Field(i).Index(j).Interface()
					b, e := element.(EDNS0).pack()
					if e != nil {
						return lenmsg, &Error{err: "overflow packing opt"}
					}
					// Option code
					msg[off], msg[off+1] = packUint16(element.(EDNS0).Option())
					// Length
					msg[off+2], msg[off+3] = packUint16(uint16(len(b)))
					off += 4
					// Actual data
					copy(msg[off:off+len(b)], b)
					off += len(b)
				}
			case `dns:"a"`:
				// It must be a slice of 4, even if it is 16, we encode
				// only the first 4
				if off+net.IPv4len > lenmsg {
					return lenmsg, &Error{err: "overflow packing a"}
				}
				switch fv.Len() {
				case net.IPv6len:
					msg[off] = byte(fv.Index(12).Uint())
					msg[off+1] = byte(fv.Index(13).Uint())
					msg[off+2] = byte(fv.Index(14).Uint())
					msg[off+3] = byte(fv.Index(15).Uint())
					off += net.IPv4len
				case net.IPv4len:
					msg[off] = byte(fv.Index(0).Uint())
					msg[off+1] = byte(fv.Index(1).Uint())
					msg[off+2] = byte(fv.Index(2).Uint())
					msg[off+3] = byte(fv.Index(3).Uint())
					off += net.IPv4len
				case 0:
					// Allowed, for dynamic updates
				default:
					return lenmsg, &Error{err: "overflow packing a"}
				}
			case `dns:"aaaa"`:
				// fv.Len TODO(mg) dynamisc updates?
				if fv.Len() > net.IPv6len || off+fv.Len() > lenmsg {
					return lenmsg, &Error{err: "overflow packing aaaa"}
				}
				for j := 0; j < net.IPv6len; j++ {
					msg[off] = byte(fv.Index(j).Uint())
					off++
				}
			case `dns:"wks"`:
				if val.Field(i).Len() == 0 {
					break
				}
				var bitmapbyte uint16
				for j := 0; j < val.Field(i).Len(); j++ {
					serv := uint16((fv.Index(j).Uint()))
					bitmapbyte = uint16(serv / 8)
					if int(bitmapbyte) > lenmsg {
						return lenmsg, &Error{err: "overflow packing wks"}
					}
					bit := uint16(serv) - bitmapbyte*8
					msg[bitmapbyte] = byte(1 << (7 - bit))
				}
				off += int(bitmapbyte)
			case `dns:"nsec"`: // NSEC/NSEC3
				// This is the uint16 type bitmap
				if val.Field(i).Len() == 0 {
					// Do absolutely nothing
					break
				}

				lastwindow := uint16(0)
				length := uint16(0)
				if off+2 > lenmsg {
					return lenmsg, &Error{err: "overflow packing nsecx"}
				}
				for j := 0; j < val.Field(i).Len(); j++ {
					t := uint16((fv.Index(j).Uint()))
					window := uint16(t / 256)
					if lastwindow != window {
						// New window, jump to the new offset
						off += int(length) + 3
						if off > lenmsg {
							return lenmsg, &Error{err: "overflow packing nsecx bitmap"}
						}
					}
					length = (t - window*256) / 8
					bit := t - (window * 256) - (length * 8)
					if off+2+int(length) > lenmsg {
						return lenmsg, &Error{err: "overflow packing nsecx bitmap"}
					}

					// Setting the window #
					msg[off] = byte(window)
					// Setting the octets length
					msg[off+1] = byte(length + 1)
					// Setting the bit value for the type in the right octet
					msg[off+2+int(length)] |= byte(1 << (7 - bit))
					lastwindow = window
				}
				off += 2 + int(length)
				off++
				if off > lenmsg {
					return lenmsg, &Error{err: "overflow packing nsecx bitmap"}
				}
			}
		case reflect.Struct:
			off, err = packStructValue(fv, msg, off, compression, compress)
			if err != nil {
				return lenmsg, err
			}
		case reflect.Uint8:
			if off+1 > lenmsg {
				return lenmsg, &Error{err: "overflow packing uint8"}
			}
			msg[off] = byte(fv.Uint())
			off++
		case reflect.Uint16:
			if off+2 > lenmsg {
				return lenmsg, &Error{err: "overflow packing uint16"}
			}
			i := fv.Uint()
			msg[off] = byte(i >> 8)
			msg[off+1] = byte(i)
			off += 2
		case reflect.Uint32:
			if off+4 > lenmsg {
				return lenmsg, &Error{err: "overflow packing uint32"}
			}
			i := fv.Uint()
			msg[off] = byte(i >> 24)
			msg[off+1] = byte(i >> 16)
			msg[off+2] = byte(i >> 8)
			msg[off+3] = byte(i)
			off += 4
		case reflect.Uint64:
			switch val.Type().Field(i).Tag {
			default:
				if off+8 > lenmsg {
					return lenmsg, &Error{err: "overflow packing uint64"}
				}
				i := fv.Uint()
				msg[off] = byte(i >> 56)
				msg[off+1] = byte(i >> 48)
				msg[off+2] = byte(i >> 40)
				msg[off+3] = byte(i >> 32)
				msg[off+4] = byte(i >> 24)
				msg[off+5] = byte(i >> 16)
				msg[off+6] = byte(i >> 8)
				msg[off+7] = byte(i)
				off += 8
			case `dns:"uint48"`:
				// Used in TSIG, where it stops at 48 bits, so we discard the upper 16
				if off+6 > lenmsg {
					return lenmsg, &Error{err: "overflow packing uint64 as uint48"}
				}
				i := fv.Uint()
				msg[off] = byte(i >> 40)
				msg[off+1] = byte(i >> 32)
				msg[off+2] = byte(i >> 24)
				msg[off+3] = byte(i >> 16)
				msg[off+4] = byte(i >> 8)
				msg[off+5] = byte(i)
				off += 6
			}
		case reflect.String:
			// There are multiple string encodings.
			// The tag distinguishes ordinary strings from domain names.
			s := fv.String()
			switch val.Type().Field(i).Tag {
			default:
				return lenmsg, &Error{"bad tag packing string: " + val.Type().Field(i).Tag.Get("dns")}
			case `dns:"base64"`:
				b64, err := packBase64([]byte(s))
				if err != nil {
					return lenmsg, &Error{err: "overflow packing base64"}
				}
				copy(msg[off:off+len(b64)], b64)
				off += len(b64)
			case `dns:"domain-name"`:
				if off, err = PackDomainName(s, msg, off, compression, false && compress); err != nil {
					return lenmsg, err
				}
			case `dns:"cdomain-name"`:
				if off, err = PackDomainName(s, msg, off, compression, true && compress); err != nil {
					return lenmsg, err
				}
			case `dns:"size-base32"`:
				// This is purely for NSEC3 atm, the previous byte must
				// holds the length of the encoded string. As NSEC3
				// is only defined to SHA1, the hashlength is 20 (160 bits)
				msg[off-1] = 20
				fallthrough
			case `dns:"base32"`:
				b32, err := packBase32([]byte(s))
				if err != nil {
					return lenmsg, &Error{err: "overflow packing base32"}
				}
				copy(msg[off:off+len(b32)], b32)
				off += len(b32)
			case `dns:"size-hex"`:
				fallthrough
			case `dns:"hex"`:
				// There is no length encoded here
				h, e := hex.DecodeString(s)
				if e != nil {
					return lenmsg, &Error{err: "overflow packing hex"}
				}
				if off+hex.DecodedLen(len(s)) > lenmsg {
					return lenmsg, &Error{err: "overflow packing hex"}
				}
				copy(msg[off:off+hex.DecodedLen(len(s))], h)
				off += hex.DecodedLen(len(s))
			case `dns:"size"`:
				// the size is already encoded in the RR, we can safely use the
				// length of string. String is RAW (not encoded in hex, nor base64)
				copy(msg[off:off+len(s)], s)
				off += len(s)
			case `dns:"txt"`:
				fallthrough
			case "":
				// Counted string: 1 byte length.
				if len(s) > 255 || off+1+len(s) > lenmsg {
					return lenmsg, &Error{err: "overflow packing string"}
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
	return off, nil
}

func structValue(any interface{}) reflect.Value {
	return reflect.ValueOf(any).Elem()
}

// PackStruct packs any structure to wire format.
func PackStruct(any interface{}, msg []byte, off int) (off1 int, err error) {
	off, err = packStructValue(structValue(any), msg, off, nil, false)
	return off, err
}

func packStructCompress(any interface{}, msg []byte, off int, compression map[string]int, compress bool) (off1 int, err error) {
	off, err = packStructValue(structValue(any), msg, off, compression, compress)
	return off, err
}

// Unpack a reflect.StructValue from msg.
// Same restrictions as packStructValue.
func unpackStructValue(val reflect.Value, msg []byte, off int) (off1 int, err error) {
	var rdstart int
	lenmsg := len(msg)
	for i := 0; i < val.NumField(); i++ {
		switch fv := val.Field(i); fv.Kind() {
		default:
			return lenmsg, &Error{err: "bad kind unpacking"}
		case reflect.Slice:
			switch val.Type().Field(i).Tag {
			default:
				return lenmsg, &Error{"bad tag unpacking slice: " + val.Type().Field(i).Tag.Get("dns")}
			case `dns:"domain-name"`:
				// HIP record slice of name (or none)
				servers := make([]string, 0)
				var s string
				for off < lenmsg {
					s, off, err = UnpackDomainName(msg, off)
					if err != nil {
						return lenmsg, err
					}
					servers = append(servers, s)
				}
				fv.Set(reflect.ValueOf(servers))
			case `dns:"txt"`:
				txt := make([]string, 0)
				rdlength := off + int(val.FieldByName("Hdr").FieldByName("Rdlength").Uint())
			Txts:
				l := int(msg[off])
				if off+l+1 > lenmsg {
					return lenmsg, &Error{err: "overflow unpacking txt"}
				}
				txt = append(txt, string(msg[off+1:off+l+1]))
				off += l + 1
				if off < rdlength {
					// More
					goto Txts
				}
				fv.Set(reflect.ValueOf(txt))
			case `dns:"opt"`: // edns0
				rdlength := int(val.FieldByName("Hdr").FieldByName("Rdlength").Uint())
				endrr := off + rdlength
				if rdlength == 0 {
					// This is an EDNS0 (OPT Record) with no rdata
					// We can safely return here.
					break
				}
				edns := make([]EDNS0, 0)
			Option:
				code := uint16(0)
				if off+2 > lenmsg {
					return lenmsg, &Error{err: "overflow unpacking opt"}
				}
				code, off = unpackUint16(msg, off)
				optlen, off1 := unpackUint16(msg, off)
				if off1+int(optlen) > off+rdlength {
					return lenmsg, &Error{err: "overflow unpacking opt"}
				}
				switch code {
				case EDNS0NSID:
					e := new(EDNS0_NSID)
					e.unpack(msg[off1 : off1+int(optlen)])
					edns = append(edns, e)
					off = off1 + int(optlen)
				case EDNS0SUBNET:
					e := new(EDNS0_SUBNET)
					e.unpack(msg[off1 : off1+int(optlen)])
					edns = append(edns, e)
					off = off1 + int(optlen)
				case EDNS0UL:
					e := new(EDNS0_UL)
					e.unpack(msg[off1 : off1+int(optlen)])
					edns = append(edns, e)
					off = off1 + int(optlen)
				case EDNS0LLQ:
					e := new(EDNS0_LLQ)
					e.unpack(msg[off1 : off1+int(optlen)])
					edns = append(edns, e)
					off = off1 + int(optlen)
				case EDNS0DAU:
					e := new(EDNS0_DAU)
					e.unpack(msg[off1 : off1+int(optlen)])
					edns = append(edns, e)
					off = off1 + int(optlen)
				case EDNS0DHU:
					e := new(EDNS0_DHU)
					e.unpack(msg[off1 : off1+int(optlen)])
					edns = append(edns, e)
					off = off1 + int(optlen)
				case EDNS0N3U:
					e := new(EDNS0_N3U)
					e.unpack(msg[off1 : off1+int(optlen)])
					edns = append(edns, e)
					off = off1 + int(optlen)
				default:
					// do nothing?
					off = off1 + int(optlen)
				}
				if off < endrr {
					goto Option
				}
				fv.Set(reflect.ValueOf(edns))
			case `dns:"a"`:
				if off+net.IPv4len > lenmsg {
					return lenmsg, &Error{err: "overflow unpacking a"}
				}
				fv.Set(reflect.ValueOf(net.IPv4(msg[off], msg[off+1], msg[off+2], msg[off+3])))
				off += net.IPv4len
			case `dns:"aaaa"`:
				if off+net.IPv6len > lenmsg {
					return lenmsg, &Error{err: "overflow unpacking aaaa"}
				}
				fv.Set(reflect.ValueOf(net.IP{msg[off], msg[off+1], msg[off+2], msg[off+3], msg[off+4],
					msg[off+5], msg[off+6], msg[off+7], msg[off+8], msg[off+9], msg[off+10],
					msg[off+11], msg[off+12], msg[off+13], msg[off+14], msg[off+15]}))
				off += net.IPv6len
			case `dns:"wks"`:
				// Rest of the record is the bitmap
				rdlength := int(val.FieldByName("Hdr").FieldByName("Rdlength").Uint())
				endrr := rdstart + rdlength
				serv := make([]uint16, 0)
				j := 0
				for off < endrr {
					b := msg[off]
					// Check the bits one by one, and set the type
					if b&0x80 == 0x80 {
						serv = append(serv, uint16(j*8+0))
					}
					if b&0x40 == 0x40 {
						serv = append(serv, uint16(j*8+1))
					}
					if b&0x20 == 0x20 {
						serv = append(serv, uint16(j*8+2))
					}
					if b&0x10 == 0x10 {
						serv = append(serv, uint16(j*8+3))
					}
					if b&0x8 == 0x8 {
						serv = append(serv, uint16(j*8+4))
					}
					if b&0x4 == 0x4 {
						serv = append(serv, uint16(j*8+5))
					}
					if b&0x2 == 0x2 {
						serv = append(serv, uint16(j*8+6))
					}
					if b&0x1 == 0x1 {
						serv = append(serv, uint16(j*8+7))
					}
					j++
					off++
				}
				fv.Set(reflect.ValueOf(serv))
			case `dns:"nsec"`: // NSEC/NSEC3
				// Rest of the record is the type bitmap
				rdlength := int(val.FieldByName("Hdr").FieldByName("Rdlength").Uint())
				endrr := rdstart + rdlength

				if off+2 > lenmsg {
					return lenmsg, &Error{err: "overflow unpacking nsecx"}
				}
				nsec := make([]uint16, 0)
				length := 0
				window := 0
				for off+2 < endrr {
					window = int(msg[off])
					length = int(msg[off+1])
					//println("off, windows, length, end", off, window, length, endrr)
					if length == 0 {
						// A length window of zero is strange. If there
						// the window should not have been specified. Bail out
						// println("dns: length == 0 when unpacking NSEC")
						return lenmsg, ErrRdata
					}
					if length > 32 {
						return lenmsg, ErrRdata
					}

					// Walk the bytes in the window - and check the bit settings...
					off += 2
					for j := 0; j < length; j++ {
						b := msg[off+j]
						// Check the bits one by one, and set the type
						if b&0x80 == 0x80 {
							nsec = append(nsec, uint16(window*256+j*8+0))
						}
						if b&0x40 == 0x40 {
							nsec = append(nsec, uint16(window*256+j*8+1))
						}
						if b&0x20 == 0x20 {
							nsec = append(nsec, uint16(window*256+j*8+2))
						}
						if b&0x10 == 0x10 {
							nsec = append(nsec, uint16(window*256+j*8+3))
						}
						if b&0x8 == 0x8 {
							nsec = append(nsec, uint16(window*256+j*8+4))
						}
						if b&0x4 == 0x4 {
							nsec = append(nsec, uint16(window*256+j*8+5))
						}
						if b&0x2 == 0x2 {
							nsec = append(nsec, uint16(window*256+j*8+6))
						}
						if b&0x1 == 0x1 {
							nsec = append(nsec, uint16(window*256+j*8+7))
						}
					}
					off += length
				}
				fv.Set(reflect.ValueOf(nsec))
			}
		case reflect.Struct:
			off, err = unpackStructValue(fv, msg, off)
			if err != nil {
				return lenmsg, err
			}
			if val.Type().Field(i).Name == "Hdr" {
				rdstart = off
			}
		case reflect.Uint8:
			if off+1 > lenmsg {
				return lenmsg, &Error{err: "overflow unpacking uint8"}
			}
			fv.SetUint(uint64(uint8(msg[off])))
			off++
		case reflect.Uint16:
			var i uint16
			if off+2 > lenmsg {
				return lenmsg, &Error{err: "overflow unpacking uint16"}
			}
			i, off = unpackUint16(msg, off)
			fv.SetUint(uint64(i))
		case reflect.Uint32:
			if off+4 > lenmsg {
				return lenmsg, &Error{err: "overflow unpacking uint32"}
			}
			fv.SetUint(uint64(uint32(msg[off])<<24 | uint32(msg[off+1])<<16 | uint32(msg[off+2])<<8 | uint32(msg[off+3])))
			off += 4
		case reflect.Uint64:
			switch val.Type().Field(i).Tag {
			default:
				if off+8 > lenmsg {
					return lenmsg, &Error{err: "overflow unpacking uint64"}
				}
				fv.SetUint(uint64(uint64(msg[off])<<56 | uint64(msg[off+1])<<48 | uint64(msg[off+2])<<40 |
					uint64(msg[off+3])<<32 | uint64(msg[off+4])<<24 | uint64(msg[off+5])<<16 | uint64(msg[off+6])<<8 | uint64(msg[off+7])))
				off += 8
			case `dns:"uint48"`:
				// Used in TSIG where the last 48 bits are occupied, so for now, assume a uint48 (6 bytes)
				if off+6 > lenmsg {
					return lenmsg, &Error{err: "overflow unpacking uint64 as uint48"}
				}
				fv.SetUint(uint64(uint64(msg[off])<<40 | uint64(msg[off+1])<<32 | uint64(msg[off+2])<<24 | uint64(msg[off+3])<<16 |
					uint64(msg[off+4])<<8 | uint64(msg[off+5])))
				off += 6
			}
		case reflect.String:
			var s string
			switch val.Type().Field(i).Tag {
			default:
				return lenmsg, &Error{"bad tag unpacking string: " + val.Type().Field(i).Tag.Get("dns")}
			case `dns:"hex"`:
				// Rest of the RR is hex encoded, network order an issue here?
				rdlength := int(val.FieldByName("Hdr").FieldByName("Rdlength").Uint())
				endrr := rdstart + rdlength
				if endrr > lenmsg {
					return lenmsg, &Error{err: "overflow unpacking hex"}
				}
				s = hex.EncodeToString(msg[off:endrr])
				off = endrr
			case `dns:"base64"`:
				// Rest of the RR is base64 encoded value
				rdlength := int(val.FieldByName("Hdr").FieldByName("Rdlength").Uint())
				endrr := rdstart + rdlength
				if endrr > lenmsg {
					return lenmsg, &Error{err: "overflow unpacking base64"}
				}
				s = unpackBase64(msg[off:endrr])
				off = endrr
			case `dns:"cdomain-name"`:
				fallthrough
			case `dns:"domain-name"`:
				s, off, err = UnpackDomainName(msg, off)
				if err != nil {
					return lenmsg, err
				}
			case `dns:"size-base32"`:
				var size int
				switch val.Type().Name() {
				case "NSEC3":
					switch val.Type().Field(i).Name {
					case "NextDomain":
						name := val.FieldByName("HashLength")
						size = int(name.Uint())
					}
				}
				if off+size > lenmsg {
					return lenmsg, &Error{err: "overflow unpacking base32"}
				}
				s = unpackBase32(msg[off : off+size])
				off += size
			case `dns:"size-hex"`:
				// a "size" string, but it must be encoded in hex in the string
				var size int
				switch val.Type().Name() {
				case "NSEC3":
					switch val.Type().Field(i).Name {
					case "Salt":
						name := val.FieldByName("SaltLength")
						size = int(name.Uint())
					case "NextDomain":
						name := val.FieldByName("HashLength")
						size = int(name.Uint())
					}
				case "TSIG":
					switch val.Type().Field(i).Name {
					case "MAC":
						name := val.FieldByName("MACSize")
						size = int(name.Uint())
					case "OtherData":
						name := val.FieldByName("OtherLen")
						size = int(name.Uint())
					}
				}
				if off+size > lenmsg {
					return lenmsg, &Error{err: "overflow unpacking hex"}
				}
				s = hex.EncodeToString(msg[off : off+size])
				off += size
			case `dns:"txt"`:
				// 1 txt piece
				rdlength := int(val.FieldByName("Hdr").FieldByName("Rdlength").Uint())
			Txt:
				if off >= lenmsg || off+1+int(msg[off]) > lenmsg {
					return lenmsg, &Error{err: "overflow unpacking txt"}
				}
				n := int(msg[off])
				off++
				for i := 0; i < n; i++ {
					s += string(msg[off+i])
				}
				off += n
				if off < rdlength {
					// More to
					goto Txt
				}
			case "":
				if off >= lenmsg || off+1+int(msg[off]) > lenmsg {
					return lenmsg, &Error{err: "overflow unpacking string"}
				}
				n := int(msg[off])
				off++
				for i := 0; i < n; i++ {
					s += string(msg[off+i])
				}
				off += n
			}
			fv.SetString(s)
		}
	}
	return off, nil
}

// Helper function for unpacking
func unpackUint16(msg []byte, off int) (v uint16, off1 int) {
	v = uint16(msg[off])<<8 | uint16(msg[off+1])
	off1 = off + 2
	return
}

// UnpackStruct unpacks a binary message from offset off to the interface
// value given.
func UnpackStruct(any interface{}, msg []byte, off int) (off1 int, err error) {
	off, err = unpackStructValue(structValue(any), msg, off)
	return off, err
}

func unpackBase32(b []byte) string {
	b32 := make([]byte, base32.HexEncoding.EncodedLen(len(b)))
	base32.HexEncoding.Encode(b32, b)
	return string(b32)
}

func unpackBase64(b []byte) string {
	b64 := make([]byte, base64.StdEncoding.EncodedLen(len(b)))
	base64.StdEncoding.Encode(b64, b)
	return string(b64)
}

// Helper function for packing
func packUint16(i uint16) (byte, byte) {
	return byte(i >> 8), byte(i)
}

func packBase64(s []byte) ([]byte, error) {
	b64len := base64.StdEncoding.DecodedLen(len(s))
	buf := make([]byte, b64len)
	n, err := base64.StdEncoding.Decode(buf, []byte(s))
	if err != nil {
		return nil, err
	}
	buf = buf[:n]
	return buf, nil
}

// Helper function for packing, mostly used in dnssec.go
func packBase32(s []byte) ([]byte, error) {
	b32len := base32.HexEncoding.DecodedLen(len(s))
	buf := make([]byte, b32len)
	n, err := base32.HexEncoding.Decode(buf, []byte(s))
	if err != nil {
		return nil, err
	}
	buf = buf[:n]
	return buf, nil
}

// Resource record packer, pack rr into msg[off:]. See PackDomainName for documentation
// about the compression.
func PackRR(rr RR, msg []byte, off int, compression map[string]int, compress bool) (off1 int, err error) {
	if rr == nil {
		return len(msg), &Error{err: "nil rr"}
	}

	off1, err = packStructCompress(rr, msg, off, compression, compress)
	if err != nil {
		return len(msg), err
	}
	rawSetRdlength(msg, off, off1)
	return off1, nil
}

// Resource record unpacker, unpack msg[off:] into an RR.
func UnpackRR(msg []byte, off int) (rr RR, off1 int, err error) {
	// unpack just the header, to find the rr type and length
	var h RR_Header
	off0 := off
	if off, err = UnpackStruct(&h, msg, off); err != nil {
		return nil, len(msg), err
	}
	end := off + int(h.Rdlength)
	// make an rr of that type and re-unpack.
	mk, known := rr_mk[h.Rrtype]
	if !known {
		rr = new(RFC3597)
	} else {
		rr = mk()
	}
	off, err = UnpackStruct(rr, msg, off0)
	if off != end {
		return &h, end, &Error{err: "bad rdlength"}
	}
	return rr, off, err
}

// Reverse a map
func reverseInt8(m map[uint8]string) map[string]uint8 {
	n := make(map[string]uint8)
	for u, s := range m {
		n[s] = u
	}
	return n
}

func reverseInt16(m map[uint16]string) map[string]uint16 {
	n := make(map[string]uint16)
	for u, s := range m {
		n[s] = u
	}
	return n
}

func reverseInt(m map[int]string) map[string]int {
	n := make(map[string]int)
	for u, s := range m {
		n[s] = u
	}
	return n
}

// Convert a MsgHdr to a string, with dig-like headers:
//
//;; opcode: QUERY, status: NOERROR, id: 48404
//
//;; flags: qr aa rd ra;
func (h *MsgHdr) String() string {
	if h == nil {
		return "<nil> MsgHdr"
	}

	s := ";; opcode: " + OpcodeToString[h.Opcode]
	s += ", status: " + RcodeToString[h.Rcode]
	s += ", id: " + strconv.Itoa(int(h.Id)) + "\n"

	s += ";; flags:"
	if h.Response {
		s += " qr"
	}
	if h.Authoritative {
		s += " aa"
	}
	if h.Truncated {
		s += " tc"
	}
	if h.RecursionDesired {
		s += " rd"
	}
	if h.RecursionAvailable {
		s += " ra"
	}
	if h.Zero { // Hmm
		s += " z"
	}
	if h.AuthenticatedData {
		s += " ad"
	}
	if h.CheckingDisabled {
		s += " cd"
	}

	s += ";"
	return s
}

// Pack packs a Msg: it is converted to to wire format.
// If the dns.Compress is true the message will be in compressed wire format.
func (dns *Msg) Pack() (msg []byte, err error) {
	var dh Header
	var compression map[string]int
	if dns.Compress {
		compression = make(map[string]int) // Compression pointer mappings
	} else {
		compression = nil
	}

	// Convert convenient Msg into wire-like Header.
	dh.Id = dns.Id
	dh.Bits = uint16(dns.Opcode)<<11 | uint16(dns.Rcode)
	if dns.Response {
		dh.Bits |= _QR
	}
	if dns.Authoritative {
		dh.Bits |= _AA
	}
	if dns.Truncated {
		dh.Bits |= _TC
	}
	if dns.RecursionDesired {
		dh.Bits |= _RD
	}
	if dns.RecursionAvailable {
		dh.Bits |= _RA
	}
	if dns.Zero {
		dh.Bits |= _Z
	}
	if dns.AuthenticatedData {
		dh.Bits |= _AD
	}
	if dns.CheckingDisabled {
		dh.Bits |= _CD
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

	// TODO(mg): still a little too much, but better than 64K...
	msg = make([]byte, dns.Len()+10)

	// Pack it in: header and then the pieces.
	off := 0
	off, err = packStructCompress(&dh, msg, off, compression, dns.Compress)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(question); i++ {
		off, err = packStructCompress(&question[i], msg, off, compression, dns.Compress)
		if err != nil {
			return nil, err
		}
	}
	for i := 0; i < len(answer); i++ {
		off, err = PackRR(answer[i], msg, off, compression, dns.Compress)
		if err != nil {
			return nil, err
		}
	}
	for i := 0; i < len(ns); i++ {
		off, err = PackRR(ns[i], msg, off, compression, dns.Compress)
		if err != nil {
			return nil, err
		}
	}
	for i := 0; i < len(extra); i++ {
		off, err = PackRR(extra[i], msg, off, compression, dns.Compress)
		if err != nil {
			return nil, err
		}
	}
	return msg[:off], nil
}

// Unpack unpacks a binary message to a Msg structure.
func (dns *Msg) Unpack(msg []byte) (err error) {
	// Header.
	var dh Header
	off := 0
	if off, err = UnpackStruct(&dh, msg, off); err != nil {
		return err
	}
	dns.Id = dh.Id
	dns.Response = (dh.Bits & _QR) != 0
	dns.Opcode = int(dh.Bits>>11) & 0xF
	dns.Authoritative = (dh.Bits & _AA) != 0
	dns.Truncated = (dh.Bits & _TC) != 0
	dns.RecursionDesired = (dh.Bits & _RD) != 0
	dns.RecursionAvailable = (dh.Bits & _RA) != 0
	dns.Zero = (dh.Bits & _Z) != 0
	dns.AuthenticatedData = (dh.Bits & _AD) != 0
	dns.CheckingDisabled = (dh.Bits & _CD) != 0
	dns.Rcode = int(dh.Bits & 0xF)

	// Arrays.
	dns.Question = make([]Question, dh.Qdcount)
	dns.Answer = make([]RR, dh.Ancount)
	dns.Ns = make([]RR, dh.Nscount)
	dns.Extra = make([]RR, dh.Arcount)

	for i := 0; i < len(dns.Question); i++ {
		off, err = UnpackStruct(&dns.Question[i], msg, off)
		if err != nil {
			return err
		}
	}
	for i := 0; i < len(dns.Answer); i++ {
		dns.Answer[i], off, err = UnpackRR(msg, off)
		if err != nil {
			return err
		}
	}
	for i := 0; i < len(dns.Ns); i++ {
		dns.Ns[i], off, err = UnpackRR(msg, off)
		if err != nil {
			return err
		}
	}
	for i := 0; i < len(dns.Extra); i++ {
		dns.Extra[i], off, err = UnpackRR(msg, off)
		if err != nil {
			return err
		}
	}
	if off != len(msg) {
		// TODO(miek) make this an error?
		// use PackOpt to let people tell how detailed the error reporting
		// should be?
		// println("dns: extra bytes in dns packet", off, "<", len(msg))
	}
	return nil
}

// Convert a complete message to a string with dig-like output.
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
			if dns.Answer[i] != nil {
				s += dns.Answer[i].String() + "\n"
			}
		}
	}
	if len(dns.Ns) > 0 {
		s += "\n;; AUTHORITY SECTION:\n"
		for i := 0; i < len(dns.Ns); i++ {
			if dns.Ns[i] != nil {
				s += dns.Ns[i].String() + "\n"
			}
		}
	}
	if len(dns.Extra) > 0 {
		s += "\n;; ADDITIONAL SECTION:\n"
		for i := 0; i < len(dns.Extra); i++ {
			if dns.Extra[i] != nil {
				s += dns.Extra[i].String() + "\n"
			}
		}
	}
	return s
}

// Len return the message length when in (un)compressed wire format.
// If dns.Compress is true compression it is taken into account, currently
// this only counts owner name compression. There is no check for
// nil valued sections (allocated, but contain no RRs).
func (dns *Msg) Len() int {
	// Message header is always 12 bytes
	l := 12
	var compression map[string]int
	if dns.Compress {
		compression = make(map[string]int)
	}

	for i := 0; i < len(dns.Question); i++ {
		l += dns.Question[i].len()
		if dns.Compress {
			compressionHelper(compression, dns.Question[i].Name)
		}
	}
	for i := 0; i < len(dns.Answer); i++ {
		if dns.Compress {
			if v, ok := compression[dns.Answer[i].Header().Name]; ok {
				l += dns.Answer[i].len() - v
				continue
			}
			compressionHelper(compression, dns.Answer[i].Header().Name)
		}
		l += dns.Answer[i].len()
	}
	for i := 0; i < len(dns.Ns); i++ {
		if dns.Compress {
			if v, ok := compression[dns.Ns[i].Header().Name]; ok {
				l += dns.Ns[i].len() - v
				continue
			}
			compressionHelper(compression, dns.Ns[i].Header().Name)
		}
		l += dns.Ns[i].len()
	}
	for i := 0; i < len(dns.Extra); i++ {
		if dns.Compress {
			if v, ok := compression[dns.Extra[i].Header().Name]; ok {
				l += dns.Extra[i].len() - v
				continue
			}
			compressionHelper(compression, dns.Extra[i].Header().Name)
		}
		l += dns.Extra[i].len()
	}
	return l
}

func compressionHelper(c map[string]int, s string) {
	pref := ""
	lbs := SplitDomainName(s)
	for j := len(lbs) - 1; j >= 0; j-- {
		c[lbs[j]+"."+pref] = 1 + len(pref) + len(lbs[j])
		pref = lbs[j] + "." + pref
	}
}

// Id return a 16 bits true random number to be used as a
// message id.
func Id() uint16 {
	id, err := rand.Int(rand.Reader, maxId)
	if err != nil {
		panic(fmt.Sprintf("Cannot generate random id: %s", err))
	}
	return uint16(id.Uint64())
}
