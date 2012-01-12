// Copyright 2009 The Go Authors. All rights reserved.
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

// RawSetRdLength sets the rdlength in the header of
// the RR. The offset 'off' must be positioned at the
// start of the header of the RR.
func RawSetRdLength(msg []byte, off, end int) bool {
	// We are at the start of the header, walk the
	// domainname (might be compressed), and set the
	// length
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
			// pointer, next byte included, ends domainnames
			off++
			break Loop
		}
	}
	// The domainname has been seen, we at the start
	// of the fixed part in the header
	// type is 2 bytes, class is 2 bytes, ttl 4 and then 2 bytes for the length
	off += 2 + 2 + 4
	if off+1 > len(msg) {
		return false
	}
        //off+1 is the end of the header, 'end' is the end of the rr
        //so 'end' - 'off+2' is the lenght of the rdata
	msg[off], msg[off+1] = packUint16(uint16(end - (off+2)))
	return true
}
