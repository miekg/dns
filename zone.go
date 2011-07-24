// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"container/vector"
)

// Zone implements the concept of RFC 1035 master zone files.
type Zone struct {
	v vector.Vector
}

// Add a new RR to the zone.
func (z *Zone) Push(r RR) {
	z.v.Push(r)
}

// Remove a RR from the zone.
func (z *Zone) Pop() RR {
	if z == nil {
		return nil
	}
	return z.v.Pop().(RR)
}

// Return the RR at index i of zone.
func (z *Zone) At(i int) RR {
        if z == nil {
                return nil
        }
	return z.v.At(i).(RR)
}

// The number of RRs in zone.
func (z *Zone) Len() int {
        if z == nil {
                return 0
        }
	return z.v.Len()
}
