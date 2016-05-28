package dns

import (
	"encoding/base32"
	"encoding/base64"
	"net"
)

// helper functions called from the generated zmsg.go

// These function are named after the tag to help pack/unpack, if there is no tag it is the name
// of the type they pack/unpack (string, int, etc). We prefix all with unpackData or packData, so packDataA or
// packDataDomainName.

func unpackDataA(msg []byte, off int) (net.IP, int, error) {
	if off+net.IPv4len > len(msg) {
		return nil, len(msg), &Error{err: "overflow unpacking a"}
	}
	a := net.IPv4(msg[off], msg[off+1], msg[off+2], msg[off+3])
	off += net.IPv4len
	return a, off, nil
}

func packDataA(a net.IP, msg []byte, off int) (int, error) {
	// It must be a slice of 4, even if it is 16, we encode only the first 4
	if off+net.IPv4len > len(msg) {
		return len(msg), &Error{err: "overflow packing a"}
	}
	switch len(a) {
	case net.IPv6len:
		msg[off] = a[12]
		msg[off+1] = a[13]
		msg[off+2] = a[14]
		msg[off+3] = a[15]
		off += net.IPv4len
	case net.IPv4len:
		msg[off] = a[0]
		msg[off+1] = a[1]
		msg[off+2] = a[2]
		msg[off+3] = a[3]
		off += net.IPv4len
	case 0:
		// Allowed, for dynamic updates.
	default:
		return len(msg), &Error{err: "overflow packing a"}
	}
	return off, nil
}

func unpackDataAAAA(msg []byte, off int) (net.IP, int, error) {
	if off+net.IPv6len > len(msg) {
		return nil, len(msg), &Error{err: "overflow unpacking aaaa"}
	}
	aaaa := net.IP{msg[off], msg[off+1], msg[off+2], msg[off+3], msg[off+4],
		msg[off+5], msg[off+6], msg[off+7], msg[off+8], msg[off+9], msg[off+10],
		msg[off+11], msg[off+12], msg[off+13], msg[off+14], msg[off+15]}
	off += net.IPv6len
	return aaaa, off, nil
}

func packDataAAAA(aaaa net.IP, msg []byte, off int) (int, error) {
	if off+net.IPv6len > len(msg) {
		return len(msg), &Error{err: "overflow packing aaaa"}
	}

	switch len(aaaa) {
	case net.IPv6len:
		msg[off] = aaaa[0]
		msg[off+1] = aaaa[1]
		msg[off+2] = aaaa[2]
		msg[off+3] = aaaa[3]
		msg[off+4] = aaaa[4]
		msg[off+5] = aaaa[5]
		msg[off+6] = aaaa[6]
		msg[off+7] = aaaa[7]
		msg[off+8] = aaaa[8]
		msg[off+9] = aaaa[9]
		msg[off+10] = aaaa[10]
		msg[off+11] = aaaa[11]
		msg[off+12] = aaaa[12]
		msg[off+13] = aaaa[13]
		msg[off+14] = aaaa[14]
		msg[off+15] = aaaa[15]
		off += net.IPv6len
	case 0:
		// Allowed, dynamic updates.
	default:
		return len(msg), &Error{err: "overflow packing aaaa"}

	}
	return off, nil
}

// unpackHeader unpacks an RR header, returning the offset to the end of the header and a
// re-sliced msg according to the expected length of the RR.
func unpackHeader(msg []byte, off int) (rr RR_Header, off1 int, truncmsg []byte, err error) {
	hdr := RR_Header{}
	if off == len(msg) {
		return hdr, off, msg, nil
	}

	hdr.Name, off, err = UnpackDomainName(msg, off)
	if err != nil {
		return hdr, len(msg), msg, err
	}
	hdr.Rrtype, off, err = unpackUint16(msg, off)
	if err != nil {
		return hdr, len(msg), msg, err
	}
	hdr.Class, off, err = unpackUint16(msg, off)
	if err != nil {
		return hdr, len(msg), msg, err
	}
	hdr.Ttl, off, err = unpackUint32(msg, off)
	if err != nil {
		return hdr, len(msg), msg, err
	}
	hdr.Rdlength, off, err = unpackUint16(msg, off)
	if err != nil {
		return hdr, len(msg), msg, err
	}
	msg, err = truncateMsgFromRdlength(msg, off, hdr.Rdlength)
	return hdr, off, msg, nil
}

// packHeader packs an RR header, returning the offset to the end of the header.
// See PackDomainName for documentation about the compression.
func packHeader(hdr RR_Header, msg []byte, off int, compression map[string]int, compress bool) (off1 int, err error) {
	if off == len(msg) {
		return off, nil
	}

	off, err = PackDomainName(hdr.Name, msg, off, compression, compress)
	if err != nil {
		return len(msg), err
	}
	off, err = packUint16(hdr.Rrtype, msg, off)
	if err != nil {
		return len(msg), err
	}
	off, err = packUint16(hdr.Class, msg, off)
	if err != nil {
		return len(msg), err
	}
	off, err = packUint32(hdr.Ttl, msg, off)
	if err != nil {
		return len(msg), err
	}
	off, err = packUint16(hdr.Rdlength, msg, off)
	if err != nil {
		return len(msg), err
	}
	return off, nil
}

// helper helper functions.

// truncateMsgFromRdLength truncates msg to match the expected length of the RR.
// Returns an error if msg is smaller than the expected size.
func truncateMsgFromRdlength(msg []byte, off int, rdlength uint16) (truncmsg []byte, err error) {
	lenrd := off + int(rdlength)
	if lenrd > len(msg) {
		return msg, &Error{err: "overflowing header size"}
	}
	return msg[:lenrd], nil
}

func fromBase32(s []byte) (buf []byte, err error) {
	buflen := base32.HexEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base32.HexEncoding.Decode(buf, s)
	buf = buf[:n]
	return
}

func fromBase64(s []byte) (buf []byte, err error) {
	buflen := base64.StdEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base64.StdEncoding.Decode(buf, s)
	buf = buf[:n]
	return
}

func unpackUint16Msg(msg []byte, off int) (uint16, int) {
	return uint16(msg[off])<<8 | uint16(msg[off+1]), off + 2
}

func packUint16Msg(i uint16) (byte, byte) { return byte(i >> 8), byte(i) }

func unpackUint32Msg(msg []byte, off int) (uint32, int) {
	return uint32(uint64(uint32(msg[off])<<24 | uint32(msg[off+1])<<16 | uint32(msg[off+2])<<8 | uint32(msg[off+3]))), off + 4
}

func packUint32Msg(i uint32) (byte, byte, byte, byte) {
	return byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)
}

func toBase32(b []byte) string { return base32.HexEncoding.EncodeToString(b) }
func toBase64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// dynamicUpdate returns true if the Rdlength is zero.
func dynamicUpdate(h RR_Header) bool { return h.Rdlength == 0 }

func unpackUint8(msg []byte, off int) (i uint8, off1 int, err error) {
	if off+1 > len(msg) {
		return 0, len(msg), &Error{err: "overflow unpacking uint8"}
	}
	return uint8(msg[off]), off + 1, nil
}

func packUint8(i uint8, msg []byte, off int) (off1 int, err error) {
	if off+2 > len(msg) {
		return len(msg), &Error{err: "overflow packing uint16"}
	}
	msg[off] = byte(i)
	return off + 1, nil
}

// unpackUint16 unpacks a uint16, computing the new offset and handling errors.
func unpackUint16(msg []byte, off int) (i uint16, off1 int, err error) {
	if off+2 > len(msg) {
		return 0, len(msg), &Error{err: "overflow unpacking uint16"}
	}
	i, off = unpackUint16Msg(msg, off)
	return i, off, nil
}

// packUint16 packs an uint16, computing the new offset and handling errors.
func packUint16(i uint16, msg []byte, off int) (off1 int, err error) {
	if off+2 > len(msg) {
		return len(msg), &Error{err: "overflow packing uint16"}
	}
	msg[off], msg[off+1] = packUint16Msg(i)
	return off + 2, nil
}

// unpackuint32 packs an uint32, computing the new offset and handling errors.
func unpackUint32(msg []byte, off int) (i uint32, off1 int, err error) {
	if off+4 > len(msg) {
		return 0, len(msg), &Error{err: "overflow unpacking uint32"}
	}
	i, off = unpackUint32Msg(msg, off)
	return i, off, nil
}

// packUint32 packs an uint32 into a struct, computing the new offset and handling errors.
func packUint32(i uint32, msg []byte, off int) (off1 int, err error) {
	if off+4 > len(msg) {
		return len(msg), &Error{err: "overflow packing uint32"}
	}
	msg[off], msg[off+1], msg[off+2], msg[off+3] = packUint32Msg(i)
	return off + 4, nil
}

func unpackUint64(msg []byte, off int, uint48 bool) (i uint64, off1 int, err error) {
	if !uint48 && off+8 > len(msg) {
		return 0, len(msg), &Error{err: "overflow unpacking uint64"}
	}
	if uint48 && off+6 > len(msg) {
		return 0, len(msg), &Error{err: "overflow unpacking uint64 as uint48"}
	}
	if uint48 {
		// Used in TSIG where the last 48 bits are occupied, so for now, assume a uint48 (6 bytes)
		i = (uint64(uint64(msg[off])<<40 | uint64(msg[off+1])<<32 | uint64(msg[off+2])<<24 | uint64(msg[off+3])<<16 |
			uint64(msg[off+4])<<8 | uint64(msg[off+5])))
		off += 6
		return i, off, nil
	}
	i = (uint64(uint64(msg[off])<<56 | uint64(msg[off+1])<<48 | uint64(msg[off+2])<<40 |
		uint64(msg[off+3])<<32 | uint64(msg[off+4])<<24 | uint64(msg[off+5])<<16 | uint64(msg[off+6])<<8 | uint64(msg[off+7])))
	off += 8
	return i, off, nil
}

// packUint64 packs an uint64 into a struct, computing the new offset and handling errors.
// If uint48 is true only the first 6 bytes are packed
func packUint64(i uint64, msg []byte, off int, uint48 bool) (off1 int, err error) {
	if !uint48 && off+8 > len(msg) {
		return len(msg), &Error{err: "overflow packing uint64"}
	}
	if uint48 && off+6 > len(msg) {
		return len(msg), &Error{err: "overflow packing uint64 as uint48"}
	}
	if uint48 {
		msg[off] = byte(i >> 40)
		msg[off+1] = byte(i >> 32)
		msg[off+2] = byte(i >> 24)
		msg[off+3] = byte(i >> 16)
		msg[off+4] = byte(i >> 8)
		msg[off+5] = byte(i)
		off += 6
		return off, nil
	}
	msg[off] = byte(i >> 56)
	msg[off+1] = byte(i >> 48)
	msg[off+2] = byte(i >> 40)
	msg[off+3] = byte(i >> 32)
	msg[off+4] = byte(i >> 24)
	msg[off+5] = byte(i >> 16)
	msg[off+6] = byte(i >> 8)
	msg[off+7] = byte(i)
	off += 8
	return off, nil
}
