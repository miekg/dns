// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS packet assembly, see RFC 1035. Converting from - Unpack() -
// and to - Pack() - wire format.
// All the packers and unpackers take a (msg []byte, off int)
// and return (off1 int, ok bool).  If they return ok==false, they
// also return off1==len(msg), so that the next unpacker will
// also fail.  This lets us avoid checks of ok until the end of a
// packing sequence.

package dns

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"math/rand"
	"net"
	"reflect"
	"strconv"
	"time"
)

const maxCompressionOffset = 2 << 13 // We have 14 bits for the compression pointer

var (
	ErrUnpack      error = &Error{Err: "unpacking failed"}
	ErrPack        error = &Error{Err: "packing failed"}
	ErrId          error = &Error{Err: "id mismatch"}
	ErrBuf         error = &Error{Err: "buffer size too large"}
	ErrShortRead   error = &Error{Err: "short read"}
	ErrConn        error = &Error{Err: "conn holds both UDP and TCP connection"}
	ErrConnEmpty   error = &Error{Err: "conn has no connection"}
	ErrServ        error = &Error{Err: "no servers could be reached"}
	ErrKey         error = &Error{Err: "bad key"}
	ErrPrivKey     error = &Error{Err: "bad private key"}
	ErrKeySize     error = &Error{Err: "bad key size"}
	ErrKeyAlg      error = &Error{Err: "bad key algorithm"}
	ErrAlg         error = &Error{Err: "bad algorithm"}
	ErrTime        error = &Error{Err: "bad time"}
	ErrNoSig       error = &Error{Err: "no signature found"}
	ErrSig         error = &Error{Err: "bad signature"}
	ErrSecret      error = &Error{Err: "no secret defined"}
	ErrSigGen      error = &Error{Err: "bad signature generation"}
	ErrAuth        error = &Error{Err: "bad authentication"}
	ErrXfrSoa      error = &Error{Err: "no SOA seen"}
	ErrXfrLast     error = &Error{Err: "last SOA"}
	ErrXfrType     error = &Error{Err: "no ixfr, nor axfr"}
	ErrHandle      error = &Error{Err: "handle is nil"}
	ErrChan        error = &Error{Err: "channel is nil"}
	ErrName        error = &Error{Err: "type not found for name"}
	ErrRRset       error = &Error{Err: "invalid rrset"}
	ErrDenialNsec3 error = &Error{Err: "no NSEC3 records"}
	ErrDenialCe    error = &Error{Err: "no matching closest encloser found"}
	ErrDenialNc    error = &Error{Err: "no covering NSEC3 found for next closer"}
	ErrDenialSo    error = &Error{Err: "no covering NSEC3 found for source of synthesis"}
	ErrDenialBit   error = &Error{Err: "type not denied in NSEC3 bitmap"}
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
	Compress bool       // If true, the message will be compressed when converted to wire format.
	Question []Question // Holds the RR(s) of the question section.
	Answer   []RR       // Holds the RR(s) of the answer section.
	Ns       []RR       // Holds the RR(s) of the authority section.
	Extra    []RR       // Holds the RR(s) of the additional section.
}

// Map of strings for each RR wire type.
var Rr_str = map[uint16]string{
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
        TypeHIP:        "HIP"
	TypeIPSECKEY:   "IPSECKEY",
	TypeSSHFP:      "SSHFP",
	TypeRRSIG:      "RRSIG",
	TypeNSEC:       "NSEC",
	TypeDNSKEY:     "DNSKEY",
	TypeNSEC3:      "NSEC3",
	TypeNSEC3PARAM: "NSEC3PARAM",
	TypeTALINK:     "TALINK",
	TypeSPF:        "SPF",
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
var Str_rr = reverseInt16(Rr_str)
var Str_class = reverseInt16(Class_str)

// Map of opcodes strings.
var Str_opcode = reverseInt(Opcode_str)

// Map of rcodes strings.
var Str_rcode = reverseInt(Rcode_str)

// Map of strings for each CLASS wire type.
var Class_str = map[uint16]string{
	ClassINET:   "IN",
	ClassCSNET:  "CS",
	ClassCHAOS:  "CH",
	ClassHESIOD: "HS",
	ClassNONE:   "NONE",
	ClassANY:    "ANY",
}

// Map of strings for opcodes.
var Opcode_str = map[int]string{
	OpcodeQuery:  "QUERY",
	OpcodeIQuery: "IQUERY",
	OpcodeStatus: "STATUS",
	OpcodeNotify: "NOTIFY",
	OpcodeUpdate: "UPDATE",
}

// Map of strings for rcodes.
var Rcode_str = map[int]string{
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
	RcodeBadSig:         "BADSIG",
	RcodeBadKey:         "BADKEY",
	RcodeBadTime:        "BADTIME",
	RcodeBadMode:        "BADMODE",
	RcodeBadName:        "BADNAME",
	RcodeBadAlg:         "BADALG",
	RcodeBadTrunc:       "BADTRUNC",
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
// map, needs to hold a mapping between domain names and offsets
// pointing into msg[].
func PackDomainName(s string, msg []byte, off int, compression map[string]int, compress bool) (off1 int, ok bool) {
	// Add trailing dot to canonicalize name.
	lenmsg := len(msg)
	if n := len(s); n == 0 || s[n-1] != '.' {
		//println("hier? s", s)
		//return lenmsg, false // This is an error, should be fqdn
		s += "."
	}

	// Each dot ends a segment of the name.
	// We trade each dot byte for a length byte.
	// Except for escaped dots (\.), which are normal dots.
	// There is also a trailing zero.
	// Check that we have all the space we need.
	tot := len(s) + 1 // TODO: this too much for compression...
	if off+tot > lenmsg {
		return lenmsg, false
	}
	// Compression
	nameoffset := -1
	pointer := -1

	// Emit sequence of counted strings, chopping at dots.
	begin := 0
	bs := []byte(s)
	ls := len(bs)
	lens := ls
	for i := 0; i < ls; i++ {
		if bs[i] == '\\' {
			for j := i; j < lens-1; j++ {
				bs[j] = bs[j+1]
			}
			ls--
			continue
		}

		if bs[i] == '.' {
			if i-begin >= 1<<6 { // top two bits of length must be clear
				return lenmsg, false
			}
			msg[off] = byte(i - begin)
			offset := off
			off++
			for j := begin; j < i; j++ {
				msg[off] = bs[j]
				off++
			}
			// Dont try to compress '.'
			if string(bs[begin:]) != "." && compression != nil {
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
						// println("Compressing:", string(bs[begin:]))
					}
				}
			}
			begin = i + 1
		}
	}
	// Root label is special
	if string(bs) == "." {
		return off, true
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

// UnpackDomainName unpacks a domain name into a string.
func UnpackDomainName(msg []byte, off int) (s string, off1 int, ok bool) {
	s = ""
	lenmsg := len(msg)
	ptr := 0 // number of pointers followed
Loop:
	for {
		if off >= lenmsg {
			return "", lenmsg, false
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
			if off+c > lenmsg {
				return "", lenmsg, false
			}
			for j := off; j < off+c; j++ {
				if msg[j] == '.' {
					// literal dot, escape it
					s += "\\."
				} else {
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
				return "", lenmsg, false
			}
			c1 := msg[off]
			off++
			if ptr == 0 {
				off1 = off
			}
			if ptr++; ptr > 10 {
				return "", lenmsg, false
			}
			off = (c^0xC0)<<8 | int(c1)
		default:
			// 0x80 and 0x40 are reserved
			return "", lenmsg, false
		}
	}
	if ptr == 0 {
		off1 = off
	}
	return s, off1, true
}

// Pack a reflect.StructValue into msg.  Struct members can only be uint8, uint16, uint32, string,
// slices and other (often anonymous) structs.
func packStructValue(val reflect.Value, msg []byte, off int, compression map[string]int, compress bool) (off1 int, ok bool) {
	for i := 0; i < val.NumField(); i++ {
		//		f := val.Type().Field(i)
		lenmsg := len(msg)
		switch fv := val.Field(i); fv.Kind() {
		default:
			return lenmsg, false
		case reflect.Slice:
			switch val.Type().Field(i).Tag {
			default:
				println("dns: unknown tag packing slice", val.Type().Field(i).Tag)
				return lenmsg, false
                        case "txt":
				for j := 0; j < val.Field(i).Len(); j++ {
                                        element := val.Field(i).Index(j).String()
                                        // Counted string: 1 byte length.
                                        if len(element) > 255 || off+1+len(element) > lenmsg {
                                                println("dns: overflow packing TXT string")
                                                return len(msg), false
                                        }
                                        msg[off] = byte(len(element))
                                        off++
                                        for i := 0; i < len(element); i++ {
                                                msg[off+i] = element[i]
                                        }
                                        off += len(element)
                                }
			case "opt": // edns
				// Length of the entire option section
				for j := 0; j < val.Field(i).Len(); j++ {
					element := val.Field(i).Index(j)
					// for each code we should do something else
					h, e := hex.DecodeString(string(element.Field(1).String()))
					if e != nil {
						println("dns: failure packing OTP")
						return lenmsg, false
					}
					code := uint16(element.Field(0).Uint())
					msg[off], msg[off+1] = packUint16(code)
					// Length
					msg[off+2], msg[off+3] = packUint16(uint16(len(string(h))))
					off += 4

					copy(msg[off:off+len(string(h))], h)
					off += len(string(h))
				}
			case "a":
				// It must be a slice of 4, even if it is 16, we encode
				// only the first 4
				switch fv.Len() {
				case net.IPv6len:
					if off+net.IPv4len > lenmsg {
						println("dns: overflow packing A", off, lenmsg)
						return lenmsg, false
					}
					msg[off] = byte(fv.Index(12).Uint())
					msg[off+1] = byte(fv.Index(13).Uint())
					msg[off+2] = byte(fv.Index(14).Uint())
					msg[off+3] = byte(fv.Index(15).Uint())
					off += net.IPv4len
				case net.IPv4len:
					if off+net.IPv4len > lenmsg {
						println("dns: overflow packing A", off, lenmsg)
						return lenmsg, false
					}
					msg[off] = byte(fv.Index(0).Uint())
					msg[off+1] = byte(fv.Index(1).Uint())
					msg[off+2] = byte(fv.Index(2).Uint())
					msg[off+3] = byte(fv.Index(3).Uint())
					off += net.IPv4len
				case 0:
					// Allowed, for dynamic updates
				default:
					println("dns: overflow packing A")
					return lenmsg, false
				}
			case "aaaa":
				if fv.Len() > net.IPv6len || off+fv.Len() > lenmsg {
					println("dns: overflow packing AAAA")
					return lenmsg, false
				}
				for j := 0; j < net.IPv6len; j++ {
					msg[off] = byte(fv.Index(j).Uint())
					off++
				}
			case "nsec": // NSEC/NSEC3
				// This is the uint16 type bitmap
				if val.Field(i).Len() == 0 {
					// Do absolutely nothing
					break
				}

				lastwindow := uint16(0)
				length := uint16(0)
				if off+2 > len(msg) {
					println("dns: overflow packing NSECx bitmap")
					return lenmsg, false
				}
				for j := 0; j < val.Field(i).Len(); j++ {
					t := uint16((fv.Index(j).Uint()))
					window := uint16(t / 256)
					if lastwindow != window {
						// New window, jump to the new offset
						off += int(length) + 3
						if off > lenmsg {
							println("dns: overflow packing NSECx bitmap")
							return lenmsg, false
						}
					}
					length = (t - window*256) / 8
					bit := t - (window * 256) - (length * 8)
					if off+2+int(length) > lenmsg {
						println("dns: overflow packing NSECx bitmap")
						return lenmsg, false
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
					println("dns: overflow packing NSECx bitmap")
					return lenmsg, false
				}
			}
		case reflect.Struct:
			off, ok = packStructValue(fv, msg, off, compression, compress)
		case reflect.Uint8:
			if off+1 > lenmsg {
				println("dns: overflow packing uint8")
				return lenmsg, false
			}
			msg[off] = byte(fv.Uint())
			off++
		case reflect.Uint16:
			if off+2 > lenmsg {
				println("dns: overflow packing uint16")
				return lenmsg, false
			}
			i := fv.Uint()
			msg[off] = byte(i >> 8)
			msg[off+1] = byte(i)
			off += 2
		case reflect.Uint32:
			if off+4 > lenmsg {
				println("dns: overflow packing uint32")
				return lenmsg, false
			}
			i := fv.Uint()
			msg[off] = byte(i >> 24)
			msg[off+1] = byte(i >> 16)
			msg[off+2] = byte(i >> 8)
			msg[off+3] = byte(i)
			off += 4
		case reflect.Uint64:
			// Only used in TSIG, where it stops at 48 bits, so we discard the upper 16
			if off+6 > lenmsg {
				println("dns: overflow packing uint64")
				return lenmsg, false
			}
			i := fv.Uint()
			msg[off] = byte(i >> 40)
			msg[off+1] = byte(i >> 32)
			msg[off+2] = byte(i >> 24)
			msg[off+3] = byte(i >> 16)
			msg[off+4] = byte(i >> 8)
			msg[off+5] = byte(i)
			off += 6
		case reflect.String:
			// There are multiple string encodings.
			// The tag distinguishes ordinary strings from domain names.
			s := fv.String()
			switch val.Type().Field(i).Tag {
			default:
				return lenmsg, false
			case "base64":
				b64, err := packBase64([]byte(s))
				if err != nil {
					println("dns: overflow packing base64")
					return lenmsg, false
				}
				copy(msg[off:off+len(b64)], b64)
				off += len(b64)
			case "domain-name":
				fallthrough // No compression
			case "cdomain-name":
				if val.Type().Field(i).Tag == "cdomain-name" {
					off, ok = PackDomainName(s, msg, off, compression, true && compress)
				} else {
					off, ok = PackDomainName(s, msg, off, compression, false && compress)
				}
				if !ok {
					println("dns: overflow packing domain-name", off)
					return lenmsg, false
				}
			case "size-base32":
				// This is purely for NSEC3 atm, the previous byte must
				// holds the length of the encoded string. As NSEC3
				// is only defined to SHA1, the hashlength is 20 (160 bits)
				msg[off-1] = 20 // Set HashLength... TODO(mg): check
				fallthrough
			case "base32":
				b32, err := packBase32([]byte(s))
				if err != nil {
					println("dns: overflow packing base32")
					return lenmsg, false
				}
				copy(msg[off:off+len(b32)], b32)
				off += len(b32)
			case "size-hex":
				fallthrough
			case "hex":
				// There is no length encoded here
				h, e := hex.DecodeString(s)
				if e != nil {
					println("dns: overflow packing (size-)hex string")
					return lenmsg, false
				}
				if off+hex.DecodedLen(len(s)) > lenmsg {
					// Overflow
					return lenmsg, false
				}
				copy(msg[off:off+hex.DecodedLen(len(s))], h)
				off += hex.DecodedLen(len(s))
			case "size":
				// the size is already encoded in the RR, we can safely use the 
				// length of string. String is RAW (not encoded in hex, nor base64)
				copy(msg[off:off+len(s)], s)
				off += len(s)
			case "txt":
				fallthrough
			case "":
				// Counted string: 1 byte length.
				if len(s) > 255 || off+1+len(s) > lenmsg {
					println("dns: overflow packing string")
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

func structValue(any interface{}) reflect.Value {
	return reflect.ValueOf(any).Elem()
}

func packStruct(any interface{}, msg []byte, off int) (off1 int, ok bool) {
	off, ok = packStructValue(structValue(any), msg, off, nil, false)
	return off, ok
}

func packStructCompress(any interface{}, msg []byte, off int, compression map[string]int, compress bool) (off1 int, ok bool) {
	off, ok = packStructValue(structValue(any), msg, off, compression, compress)
	return off, ok
}

// Unpack a reflect.StructValue from msg.
// Same restrictions as packStructValue.
func unpackStructValue(val reflect.Value, msg []byte, off int) (off1 int, ok bool) {
	for i := 0; i < val.NumField(); i++ {
		//		f := val.Type().Field(i)
		lenmsg := len(msg)
		switch fv := val.Field(i); fv.Kind() {
		default:
			println("dns: unknown case unpacking struct")
			return lenmsg, false
		case reflect.Slice:
			switch val.Type().Field(i).Tag {
			default:
				println("dns: unknown tag unpacking slice", val.Type().Field(i).Tag)
				return lenmsg, false
                        case "txt":
                                txt := make([]string,0)
				rdlength := int(val.FieldByName("Hdr").FieldByName("Rdlength").Uint())
                        Txts:
                                l := int(msg[off])
                                if off + l + 1 > lenmsg {
                                        println("dns: failure unpacking txt strings")
                                        return lenmsg, false
                                }
                                txt = append(txt, string(msg[off+1:off+l+1]))
                                off += l+1
                                if off < rdlength {
                                        // More
                                        goto Txts
                                }
				fv.Set(reflect.ValueOf(txt))
			case "opt": // edns0
				if off+2 > lenmsg {
					// This is an EDNS0 (OPT Record) with no rdata
					// We can savely return here.
					break
				}
				opt := make([]Option, 1)
				opt[0].Code, off = unpackUint16(msg, off)
				optlen, off1 := unpackUint16(msg, off)
				if off1+int(optlen) > lenmsg {
					println("dns: overflow unpacking OPT")
					return lenmsg, false
				}
				opt[0].Data = hex.EncodeToString(msg[off1 : off1+int(optlen)])
				fv.Set(reflect.ValueOf(opt))
				off = off1 + int(optlen)
			case "a":
				if off+net.IPv4len > len(msg) {
					println("dns: overflow unpacking A")
					return lenmsg, false
				}
				fv.Set(reflect.ValueOf(net.IPv4(msg[off], msg[off+1], msg[off+2], msg[off+3])))
				off += net.IPv4len
			case "aaaa":
				if off+net.IPv6len > lenmsg {
					println("dns: overflow unpacking AAAA")
					return lenmsg, false
				}
				fv.Set(reflect.ValueOf(net.IP{msg[off], msg[off+1], msg[off+2], msg[off+3], msg[off+4],
					msg[off+5], msg[off+6], msg[off+7], msg[off+8], msg[off+9], msg[off+10],
					msg[off+11], msg[off+12], msg[off+13], msg[off+14], msg[off+15]}))
				off += net.IPv6len
			case "nsec": // NSEC/NSEC3
				// Rest of the Record is the type bitmap
				rdlength := int(val.FieldByName("Hdr").FieldByName("Rdlength").Uint())
				var endrr int
				// for NSEC and NSEC3 calculate back what end of the RR must be
				switch val.Type().Name() {
				case "RR_NSEC":
					endrr = off + (rdlength - (len(val.FieldByName("NextDomain").String()) + 1))
				case "RR_NSEC3":
					// NextDomain is always 20 for NextDomain
					endrr = off + (rdlength - (20 + 6 + len(val.FieldByName("Salt").String())/2))
				}

				if off+2 > lenmsg {
					println("dns: overflow unpacking NSEC")
					return lenmsg, false
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
						println("dns: length == 0 when unpacking NSEC")
						return lenmsg, false
					}
					if length > 32 {
						println("dns: length > 32 when unpacking NSEC")
						return lenmsg, false
					}

					// Walk the bytes in the window - and check the bit
					// setting..
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
			off, ok = unpackStructValue(fv, msg, off)
		case reflect.Uint8:
			if off+1 > lenmsg {
				println("dns: overflow unpacking uint8")
				return lenmsg, false
			}
			fv.SetUint(uint64(uint8(msg[off])))
			off++
		case reflect.Uint16:
			var i uint16
			if off+2 > lenmsg {
				println("dns: overflow unpacking uint16")
				return lenmsg, false
			}
			i, off = unpackUint16(msg, off)
			fv.SetUint(uint64(i))
		case reflect.Uint32:
			if off+4 > lenmsg {
				println("dns: overflow unpacking uint32")
				return lenmsg, false
			}
			fv.SetUint(uint64(uint32(msg[off])<<24 | uint32(msg[off+1])<<16 | uint32(msg[off+2])<<8 | uint32(msg[off+3])))
			off += 4
		case reflect.Uint64:
			// This is *only* used in TSIG where the last 48 bits are occupied
			// So for now, assume a uint48 (6 bytes)
			if off+6 > lenmsg {
				println("dns: overflow unpacking uint64")
				return lenmsg, false
			}
			fv.SetUint(uint64(uint64(msg[off])<<40 | uint64(msg[off+1])<<32 | uint64(msg[off+2])<<24 | uint64(msg[off+3])<<16 |
				uint64(msg[off+4])<<8 | uint64(msg[off+5])))
			off += 6
		case reflect.String:
			var s string
			switch val.Type().Field(i).Tag {
			default:
				println("dns: unknown tag unpacking string")
				return lenmsg, false
			case "hex":
				// Rest of the RR is hex encoded, network order an issue here?
				rdlength := int(val.FieldByName("Hdr").FieldByName("Rdlength").Uint())
				var consumed int
				switch val.Type().Name() {
				case "RR_DS":
					consumed = 4 // KeyTag(2) + Algorithm(1) + DigestType(1)
				case "RR_SSHFP":
					consumed = 2 // Algorithm(1) + Type(1)
				case "RR_NSEC3PARAM":
					consumed = 5 // Hash(1) + Flags(1) + Iterations(2) + SaltLength(1)
				case "RR_RFC3597":
					fallthrough // Rest is the unknown data
				default:
					consumed = 0 // return len(msg), false?
				}
				if off+rdlength-consumed > lenmsg {
					println("dns: overflow when unpacking hex string")
					return lenmsg, false
				}
				s = hex.EncodeToString(msg[off : off+rdlength-consumed])
				off += rdlength - consumed
			case "base64":
				// Rest of the RR is base64 encoded value
				rdlength := int(val.FieldByName("Hdr").FieldByName("Rdlength").Uint())
				// Need to know how much of rdlength is already consumed, in this packet
				var consumed int
				switch val.Type().Name() {
				case "RR_DNSKEY":
					consumed = 4 // Flags(2) + Protocol(1) + Algorithm(1)
				case "RR_RRSIG":
					consumed = 18 // TypeCovered(2) + Algorithm(1) + Labels(1) +
					// OrigTTL(4) + SigExpir(4) + SigIncep(4) + KeyTag(2) + len(signername)
					// Should already be set in the sequence of parsing (comes before)
					// Work because of rfc4034, section 3.17
					consumed += len(val.FieldByName("SignerName").String()) + 1
				default:
					consumed = 0 // TODO, maybe error?
				}
				if off+rdlength-consumed > lenmsg {
					println("dns: failure unpacking base64")
					return lenmsg, false
				}
				s = unpackBase64(msg[off : off+rdlength-consumed])
				off += rdlength - consumed
			case "cdomain-name":
				fallthrough
			case "domain-name":
				s, off, ok = UnpackDomainName(msg, off)
				if !ok {
					println("dns: failure unpacking domain-name")
					return lenmsg, false
				}
			case "size-base32":
				var size int
				switch val.Type().Name() {
				case "RR_NSEC3":
					switch val.Type().Field(i).Name {
					case "NextDomain":
						name := val.FieldByName("HashLength")
						size = int(name.Uint())
					}
				}
				if off+size > lenmsg {
					println("dns: failure unpacking size-base32 string")
					return lenmsg, false
				}
				s = unpackBase32(msg[off : off+size])
				off += size
			case "size-hex":
				// a "size" string, but it must be encoded in hex in the string
				var size int
				switch val.Type().Name() {
				case "RR_NSEC3":
					switch val.Type().Field(i).Name {
					case "Salt":
						name := val.FieldByName("SaltLength")
						size = int(name.Uint())
					case "NextDomain":
						name := val.FieldByName("HashLength")
						size = int(name.Uint())
					}
				case "RR_TSIG":
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
					println("dns: failure unpacking size-hex string")
					return lenmsg, false
				}
				s = hex.EncodeToString(msg[off : off+size])
				off += size
			case "txt":
				// 1 txt piece
				rdlength := int(val.FieldByName("Hdr").FieldByName("Rdlength").Uint())
			Txt:
				if off >= lenmsg || off+1+int(msg[off]) > lenmsg {
					println("dns: failure unpacking txt string")
					return lenmsg, false
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
					println("dns: failure unpacking string")
					return lenmsg, false
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
	return off, true
}

// Helper function for unpacking
func unpackUint16(msg []byte, off int) (v uint16, off1 int) {
	v = uint16(msg[off])<<8 | uint16(msg[off+1])
	off1 = off + 2
	return
}

func unpackStruct(any interface{}, msg []byte, off int) (off1 int, ok bool) {
	off, ok = unpackStructValue(structValue(any), msg, off)
	return off, ok
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

// Resource record packer.
func packRR(rr RR, msg []byte, off int, compression map[string]int, compress bool) (off1 int, ok bool) {
	if rr == nil {
		return len(msg), false
	}

	off1, ok = packStructCompress(rr, msg, off, compression, compress)
	if !ok {
		return len(msg), false
	}
	RawSetRdlength(msg, off, off1)
	return off1, true
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
	mk, known := rr_mk[h.Rrtype]
	if !known {
		rr = new(RR_RFC3597)
	} else {
		rr = mk()
	}
	off, ok = unpackStruct(rr, msg, off0)
	if off != end {
		return &h, end, true
	}
	return rr, off, ok
}

// Reverse a map
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

// Convert a MsgHdr to a string, mimic the way Dig displays headers:
//
//;; opcode: QUERY, status: NOERROR, id: 48404
//
//;; flags: qr aa rd ra;
func (h *MsgHdr) String() string {
	if h == nil {
		return "<nil> MsgHdr"
	}

	s := ";; opcode: " + Opcode_str[h.Opcode]
	s += ", status: " + Rcode_str[h.Rcode]
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
func (dns *Msg) Pack() (msg []byte, ok bool) {
	var dh Header
	compression := make(map[string]int) // Compression pointer mappings

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

	// TODO: still a little too much, but better than 64K...
	msg = make([]byte, dns.Len()*2)

	// Pack it in: header and then the pieces.
	off := 0
	off, ok = packStructCompress(&dh, msg, off, compression, dns.Compress)
	for i := 0; i < len(question); i++ {
		off, ok = packStructCompress(&question[i], msg, off, compression, dns.Compress)
	}
	for i := 0; i < len(answer); i++ {
		off, ok = packRR(answer[i], msg, off, compression, dns.Compress)
	}
	for i := 0; i < len(ns); i++ {
		off, ok = packRR(ns[i], msg, off, compression, dns.Compress)
	}
	for i := 0; i < len(extra); i++ {
		off, ok = packRR(extra[i], msg, off, compression, dns.Compress)
	}
	if !ok {
		return nil, false
	}
	return msg[:off], true
}

// Unpack unpacks a binary message to a Msg structure.
func (dns *Msg) Unpack(msg []byte) bool {
	// Header.
	var dh Header
	off := 0
	var ok bool
	if off, ok = unpackStruct(&dh, msg, off); !ok {
		return false
	}
	dns.Id = dh.Id
	dns.Response = (dh.Bits & _QR) != 0
	dns.Opcode = int(dh.Bits>>11) & 0xF
	dns.Authoritative = (dh.Bits & _AA) != 0
	dns.Truncated = (dh.Bits & _TC) != 0
	dns.RecursionDesired = (dh.Bits & _RD) != 0
	dns.RecursionAvailable = (dh.Bits & _RA) != 0
	dns.Rcode = int(dh.Bits & 0xF)

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
		// TODO(mg) remove eventually
		println("extra bytes in dns packet", off, "<", len(msg))
	}
	return true
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

// Len return the message length when in uncompressed wire format.
func (dns *Msg) Len() int {
	// Message header is always 12 bytes       
	l := 12
	if len(dns.Question) > 0 {
		for i := 0; i < len(dns.Question); i++ {
			l += dns.Question[i].Len()
		}
	}
	if len(dns.Answer) > 0 {
		for i := 0; i < len(dns.Answer); i++ {
			l += dns.Answer[i].Len()
		}
	}
	if len(dns.Ns) > 0 {
		for i := 0; i < len(dns.Ns); i++ {
			l += dns.Ns[i].Len()
		}
	}
	if len(dns.Extra) > 0 {
		for i := 0; i < len(dns.Extra); i++ {
			l += dns.Extra[i].Len()
		}
	}
	return l
}

// CompressedLen returns the length of the message when in 
// compressed wire format.
func (dns *Msg) CompressedLen() int {
	// Uhh. TODO
	return 0
}

// Id return a 16 bits random number to be used as a
// message id. The random provided should be good enough.
func Id() uint16 {
	return uint16(rand.Int()) ^ uint16(time.Now().Nanosecond())
}
