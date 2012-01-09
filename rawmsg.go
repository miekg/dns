// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"fmt"
)

const maxPointer = 2 << 13 // We have 14 bits for the offset

// Function defined in this subpackage work on []byte and but still
// provide some higher level functions.

// RawSetId sets the message ID in buf.
func RawSetId(msg []byte, off int, id uint16) bool {
	msg[off], msg[off+1] = packUint16(id)
	return true
}

type rawlabel struct {
	offset int    // offset where this labels starts in the msg buf
	name   string // the label, not this includes the length at the start
}

type rawmove struct {
	offset int // where to point to
	from   int // where in the buffer set the pointer
	length int // used in calculating how much to shrink the message
}

// Compress performs name comression in the dns message contained in buf.
// It returns the number of bytes saved.
func Compress(msg []byte) int {

	// First we create a table of domain names to which we 
	// can link. This is stored in 'table'
	// Once for another name the longest possible link is
	// found we save how we must change msg to perform this
	// compression. This is saved in 'moves'. After we
	// traversed the entire message, we perform all the
	// moves.
	// TODO: Maybe it should be optimized.

	// Map the labels to the offset in the message
	table := make(map[string]int)
	moves := make([]rawmove, 0)
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
				poffset := 0 // Where to point to
				moffset := 0 // From where to insert the pointer
				for j := i - 1; j >= 0; j-- {
					name = l[j].name + name
					if idx, ok := table[name]; !ok {
						table[name] = l[j].offset
					} else {
						poffset = idx
						moffset = l[j].offset
					}
				}
				if poffset != 0 {
					//println("We kunnen verwijzen naar", poffset, "vanaf", moffset, "voor", name)
					//println("met lengte", len(name)+1)
					// the +1 for the name is for the null byte at the end

                                        // Discount for previous moves, reset the poffset counter
                                        for i := len(moves)-1; i >= 0; i-- {
                                                if poffset > moves[i].from {
                                                        poffset -= (moves[i].length - 2)
                                                }
                                        }

					moves = append(moves, rawmove{offset: poffset, from: moffset, length: len(name) + 1})
				}

				// end of the name
				if question {
					// In question section
					off += 4 // type, class + 1
					question = false
				} else {
					// How to handle well known records here
					// NS, MX, CNAME? eatName() function?
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
			// If we are too deep in the message we cannot point to
			// it, so skip this label.
			if off < maxPointer {
				l[i] = rawlabel{offset: off, name: string(msg[off : off+c+1])}
				i++
			}
			// save the new names 
			off += c + 1
		default:
			break Loop
		}
	}
	//	fmt.Printf("table %v\n", table)
	//	fmt.Printf("moves %v\n", moves)

	saved := 0
	// Start at the back, easier to move
	for i := len(moves) - 1; i >= 0; i-- {
		fmt.Printf("%v\n", moves[i])
		// move the bytes
                copy(msg[moves[i].from+1:], msg[moves[i].from+moves[i].length-1:])
		// Now set the pointer at moves[i].from and moves[i].from+1
		fmt.Printf("bits %b\n", moves[i].offset^0xC000)
		msg[moves[i].from], msg[moves[i].from+1] = packUint16(uint16(moves[i].offset ^ 0xC000))
		saved += moves[i].length // minus something
	}
	return saved
}
