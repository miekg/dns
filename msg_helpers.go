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
	lenmsg := len(msg)
	if dynamicUpdate(off, lenmsg) {
		return nil, off, nil
	}
	if off+net.IPv4len > lenmsg {
		return nil, lenmsg, &Error{err: "overflow unpacking a"}
	}
	a := net.IPv4(msg[off], msg[off+1], msg[off+2], msg[off+3])
	off += net.IPv4len
	return a, off, nil
}

func packDataA(a net.IP, msg []byte, off int) (int, error) {
	lenmsg := len(msg)
	// It must be a slice of 4, even if it is 16, we encode only the first 4
	if off+net.IPv4len > lenmsg {
		return lenmsg, &Error{err: "overflow packing a"}
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
		// Allowed, for dynamic updates
	default:
		return lenmsg, &Error{err: "overflow packing a"}
	}
	return off, nil
}

func unpackDataAAAA(msg []byte, off int) (net.IP, int, error) {
	lenmsg := len(msg)
	if dynamicUpdate(off, lenmsg) {
		return nil, off, nil
	}
	if off+net.IPv6len > lenmsg {
		return nil, lenmsg, &Error{err: "overflow unpacking aaaa"}
	}
	aaaa := net.IP{msg[off], msg[off+1], msg[off+2], msg[off+3], msg[off+4],
		msg[off+5], msg[off+6], msg[off+7], msg[off+8], msg[off+9], msg[off+10],
		msg[off+11], msg[off+12], msg[off+13], msg[off+14], msg[off+15]}
	off += net.IPv6len
	return aaaa, off, nil
}

func packDataAAAA(aaaa net.IP, msg []byte, off int) (int, error) {
	lenmsg := len(msg)
	laaaa := len(aaaa)

	if laaaa > net.IPv6len || off+laaaa > lenmsg {
		return lenmsg, &Error{err: "overflow packing aaaa"}
	}
	for i := 0; i < net.IPv6len; i++ {
		msg[off] = aaaa[i]
		off++
	}
	return off, nil
}

// unpackHeader unpacks an RR header, returning the offset to the end of the header and a
// re-sliced msg according to the expected length of the RR.
func unpackHeader(hdr *RR_Header, msg []byte, off int) (off1 int, truncmsg []byte, err error) {
	lenmsg := len(msg)
	if off == lenmsg {
		return off, msg, nil
	}
	hdr.Name, off, err = UnpackDomainName(msg, off)
	if err != nil {
		return lenmsg, msg, err
	}
	hdr.Rrtype, off, err = unpackStructUint16(msg, off, lenmsg)
	if err != nil {
		return lenmsg, msg, err
	}
	hdr.Class, off, err = unpackStructUint16(msg, off, lenmsg)
	if err != nil {
		return lenmsg, msg, err
	}
	hdr.Ttl, off, err = unpackStructUint32(msg, off, lenmsg)
	if err != nil {
		return lenmsg, msg, err
	}
	hdr.Rdlength, off, err = unpackStructUint16(msg, off, lenmsg)
	if err != nil {
		return lenmsg, msg, err
	}
	msg, err = truncateMsgFromRdlength(msg, off, hdr.Rdlength)
	return off, msg, nil
}

// packHeader packs an RR header, returning the offset to the end of the header.
// See PackDomainName for documentation about the compression.
func packHeader(hdr RR_Header, msg []byte, off int, compression map[string]int, compress bool) (off1 int, err error) {
	lenmsg := len(msg)
	if off == lenmsg {
		return off, nil
	}
	off, err = PackDomainName(hdr.Name, msg, off, compression, compress)
	if err != nil {
		return lenmsg, err
	}
	off, err = packStructUint16(hdr.Rrtype, msg, off, lenmsg)
	if err != nil {
		return lenmsg, err
	}
	off, err = packStructUint16(hdr.Class, msg, off, lenmsg)
	if err != nil {
		return lenmsg, err
	}
	off, err = packStructUint32(hdr.Ttl, msg, off, lenmsg)
	if err != nil {
		return lenmsg, err
	}
	off, err = packStructUint16(hdr.Rdlength, msg, off, lenmsg)
	if err != nil {
		return lenmsg, err
	}
	return off, nil
}

// helper helper functions.

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

func unpackUint16(msg []byte, off int) (uint16, int) {
	return uint16(msg[off])<<8 | uint16(msg[off+1]), off + 2
}

func packUint16(i uint16) (byte, byte) { return byte(i >> 8), byte(i) }
func toBase32(b []byte) string         { return base32.HexEncoding.EncodeToString(b) }
func toBase64(b []byte) string         { return base64.StdEncoding.EncodeToString(b) }

// dynamicUpdate returns true of off equals len.
func dynamicUpdate(off, len int) bool { return off == len }
