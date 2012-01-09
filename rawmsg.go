// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
        "fmt"
)

// Function defined in this subpackage work on []byte and but still
// provide some higher level functions.

// RawSetId sets the message ID in buf.
func RawSetId(msg []byte, off int, id uint16) bool {
	msg[off], msg[off+1] = packUint16(id)
	return true
}

type rawlabel struct {
        offset  int     // offset where this labels starts in the msg buf
        str     string  // the label, not this includes the length at the start
}

// Compress performs name comression in the dns message contained in buf.
// It returns the number of dnames compressed.
func Compress(msg []byte) int {

	// Map the labels to the offset in the message
	table := make(map[string]int)
	l := make([]rawlabel, 127) // Max labels?
	i := 0

	// Very much like the loop in msg.go
	off := 12 // Start of the first name in the q section
	question := true
Loop:
	for {
		c := int(msg[off])
		switch c & 0xC0 {
		case 0x00:
			if c == 0x00 {
				// Do all of the bookkeeping

                                name := ""
                                poffset := 0      // Where to point to
                                moffset := 0          // From where to insert the pointer
				for j := i-1; j >= 0; j-- {
                                        name = l[j].str + name
                                        if idx, ok := table[name]; !ok {
                                                table[name] = l[j].offset
                                        } else {
                                                poffset = idx
                                                moffset = l[j].offset
                                        }
				}
                                if poffset == 0 {
                                        println("niks gevonden, nieuw!")
                                } else {
                                        println("We kunnen verwijzen naar", poffset, "vanaf", moffset)
                                }

				// end of the name
				if question {
					// In question section
					off += 4 // type, class + 1
					question = false
				} else {
					// In the "body" of the msg
					off += 2 + 2 + 4 + 1 // type, class, ttl + 1     
					// we are at the rdlength
					rdlength, _ := unpackUint16(msg, off)
					off += int(rdlength) + 1 // Skip the rdata
				}
                                off++
				if off+1 > len(msg) {
					break Loop
				}
				i = 0
                                continue Loop
			}

			if off+c+1 > len(msg) {
				break Loop
			}
			// c is the mount to scan forward
                        l[i] = rawlabel{offset: off, str: string(msg[off : off+c+1])}
			i++
			// save the new names 
			off += c + 1
		default:
			break Loop
		}
	}
        fmt.Printf("table %v\n", table)

	return 0
}
