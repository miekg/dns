// Copyright 2012 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

// Function defined in this subpackage work on []byte and but still
// provide some higher level functions.

// RawSetId sets the message ID in buf. The offset 'off' must
// be positioned at the beginning of the message.
func RawSetId(msg []byte, off int, id uint16) bool {
	msg[off], msg[off+1] = packUint16(id)
	return true
}

// RawSetRdlength sets the rdlength in the header of
// the RR. The offset 'off' must be positioned at the
// start of the header of the RR, 'end' must be the
// end of the RR.
func RawSetRdlength(msg []byte, off, end int) bool {
	// We are at the start of the header, walk the domainname (might be compressed)
Loop:
	for {
		if off > len(msg) {
			return false
		}
		c := int(msg[off])
		off++
		switch c & 0xC00 {
		case 0x00:
			if c == 0x00 {
				// End of the domainname
				break Loop
			}

		case 0xC0:
			// pointer, next byte included, ends domainname
			off++
			break Loop
		}
	}
	// The domainname has been seen, we at the start of the fixed part in the header.
	// Type is 2 bytes, class is 2 bytes, ttl 4 and then 2 bytes for the length.
	off += 2 + 2 + 4
	if off+1 > len(msg) {
		return false
	}
	//off+1 is the end of the header, 'end' is the end of the rr
	//so 'end' - 'off+2' is the lenght of the rdata
	msg[off], msg[off+1] = packUint16(uint16(end - (off + 2)))
	return true
}

// RawSetRdlength return the type and length as found
// in the RR header.
func RawTypeRdlength(msg []byte, off int) (uint16, uint16, int) {
Loop:
	for {
		if off > len(msg) {
			return 0, 0, off
		}
		c := int(msg[off])
		off++
		switch c & 0xC00 {
		case 0x00:
			if c == 0x00 {
				// End of the domainname
				break Loop
			}

		case 0xC0:
			// pointer, next byte included, ends domainnames
			off++
			break Loop
		}
	}
	off--
	if off+8 > len(msg) {
		return 0, 0, off
	}
	t, off := unpackUint16(msg, off)   // type
	l, off := unpackUint16(msg, off+6) // length
	return t, l, off
}
