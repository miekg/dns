// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

// Function defined in this subpackage work on []byte and but still
// provide some higher level functions.

// SetRdlength sets the length of the length of the rdata
// directly at the correct position in the buffer buf.
// If buf does not look like a DNS message false is returned,
// otherwise true.
func (h *RR_Header) RawSetRdlength(buf []byte, off int) bool {
	off1 := DomainNameLength(h.Name)
	if off1 == 0 || len(buf) < off+off1+2+2+4+1 {
		return false
	}
	// + type(2) + class(2) + ttl(4) is where rdlength it at
	buf[off+off1+2+2+4], buf[off+off1+2+2+4+1] = packUint16(h.Rdlength)
	return true
}

// RawSetId sets the message ID in buf.
func RawSetId(buf []byte, off int, id uint16) bool {
	buf[off], buf[off+1] = packUint16(id)
	return true
}
