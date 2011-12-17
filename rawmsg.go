// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

// Function defined in this subpackage work on []byte and but still
// provide some higher level functions.

// RawSetId sets the message ID in buf.
func RawSetId(buf []byte, off int, id uint16) bool {
	buf[off], buf[off+1] = packUint16(id)
	return true
}
