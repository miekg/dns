package dns

import (
	"encoding/base32"
	"encoding/base64"
	"net"
)

// helper functions called from the generated zmsg.go

// These function are named after the tag the help pack/unpack, if there is no tag it is the name
// of the type they pack/unpack (string, int, etc). We prefix all with unpack or pack, so packA or
// packDomainName.

func unpackA(msg []byte, off int) (a net.IP, off1 int, err error) {
	lenmsg := len(msg)
	if off == lenmsg {
		return nil, off, nil // dyn. update
	}
	if off+net.IPv4len > lenmsg {
		return nil, lenmsg, &Error{err: "overflow unpacking a"}
	}
	a = net.IPv4(msg[off], msg[off+1], msg[off+2], msg[off+3])
	off += net.IPv4len
	return a, off, nil
}

func packA(a net.IP, msg []byte, off int) (off1 int, err error) {
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
