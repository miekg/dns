// Copyright 2012 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

// RawSetId sets the message ID in buf.
func RawSetId(msg []byte, i uint16) {
	msg[0], msg[1] = packUint16(i)
}

// RawSetQuestionLen sets the len of the question section.
func RawSetQuestionLen(msg []byte, i uint16) {
	msg[4], msg[5] = packUint16(i)
}

// RawSetAnswerLen sets the len of the question section.
func RawSetAnswerLen(msg []byte, i uint16) {
	msg[6], msg[7] = packUint16(i)
}

// RawSetsNsLen sets the len of the question section.
func RawSetNsLen(msg []byte, i uint16) {
	msg[8], msg[9] = packUint16(i)
}

// RawSetExtraLen sets the len of the question section.
func RawSetExtraLen(msg []byte, i uint16) {
	msg[10], msg[11] = packUint16(i)
}

// RawSetRdlength sets the rdlength in the header of
// the RR. The offset 'off' must be positioned at the
// start of the header of the RR, 'end' must be the
// end of the RR. There is no check if we overrun the buffer.
func RawSetRdlength(msg []byte, off, end int) {
	// We are at the start of the header, walk the domainname (might be compressed)
Loop:
	for {
		c := int(msg[off])
		off++
		switch c & 0xC0 {
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
	//off+1 is the end of the header, 'end' is the end of the rr
	//so 'end' - 'off+2' is the lenght of the rdata
	msg[off], msg[off+1] = packUint16(uint16(end - (off + 2)))
	return
}
