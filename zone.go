// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Implements a concept of zones. In its most basic form
// a list of RRs. 
package dns

import (
        "container/vector"
)

type Zone struct {
        v vector.Vector
}

func (z *Zone) Push(r RR) {
        z.v.Push(r)
}

func (z *Zone) Pop() RR {
        return z.v.Pop().(RR)
}

func (z *Zone) At(i int) RR {
        return z.v.At(i).(RR)
}

func (z *Zone) Len() int {
        return z.v.Len()
}

func (z *Zone) String() (s string) {
        for i:=0; i < z.Len(); i++ {
                s += z.At(i).String() + "\n"
        }
        return
}
