// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

/* Function defined in this subpackage work on []byte and but still
 * provide some higher level functions
 */


// SetRdlength sets the length of the length of the rdata
// directly at the correct position in the buffer buf.
// If buf does not look like a DNS message false is returned,
// otherwise true.
func RawSetRdlength(buf []byte, i uint16) bool {
        var off int
        var ok bool
	if _, off, ok = unpackDomainName(buf, 0); !ok {
		return false
	}
        // off + type(2) + class(2) + ttl(4) -> rdlength
        buf[off+2+2+4], buf[off+2+2+4+1] = packUint16(i)
        return true
}
