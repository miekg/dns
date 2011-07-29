// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"os"
)

const _CLASS = 2 << 16

// ZRRset is a structure that keeps several items from
// a zone file together. It  helps in speeding up DNSSEC lookups.
type ZRRset struct {
	RRs    RRset // the RRset for this type and name
	RRsigs RRset // the RRSIGs belonging to this RRset (if any)
	Nxt    RR    // the NSEC or NSEC3 for this name
	Glue   bool  // when this RRset is glue, set to true
}

func NewZRRset() *ZRRset {
	s := new(ZRRset)
	s.RRs = NewRRset()
	s.RRsigs = NewRRset()
	return s
}

// Zone implements the concept of RFC 1035 master zone files.
// This will be converted to some kind of tree structure
type Zone map[string]map[int]*ZRRset

func NewZone() Zone {
	z := make(Zone)
	return z
}

// Get the first value 
func (z Zone) Pop() *ZRRset {
	for _, v := range z {
		for _, v1 := range v {
			return v1
		}
	}
	return nil
}

func (z Zone) PopRR() RR {
	s := z.Pop()
	if s == nil {
		return nil
	}
	// differentiate between the type 'n stuff
	return s.RRs.Pop()
}

func (z Zone) Len() int {
	i := 0
	for _, im := range z {
		for _, s := range im {
			i += len(s.RRs) + len(s.RRsigs)
                        if s.Nxt != nil {
                                i++
                        }
		}
	}
	return i
}

func (z Zone) String() string {
	s := ""
	for _, im := range z {
		for _, s1 := range im {
			s += s1.RRs.String()
			s += s1.RRsigs.String()
                        if s1.Nxt != nil {
                                s += s1.Nxt.String()
                        }
		}
	}
	return s
}

// Create a debug output of the zone
func (z Zone) DebugString() string {
        s := ""
	for name, im := range z {
                s += "Data for: [" + name + "]\n"
		for _, s1 := range im {
			s += s1.RRs.String()
			s += s1.RRsigs.String()
                        if s1.Nxt != nil {
                                s += s1.Nxt.String()
                        }
		}
                s += "\n"
	}
	return s

}

// Add a new RR to the zone. First we need to find out if the 
// RR already lives inside it.
func (z Zone) PushRR(r RR) {
	s, _ := z.LookupRR(r)
	if s == nil {
		s = NewZRRset()
	}
	switch r.Header().Rrtype {
	case TypeRRSIG:
		s.RRsigs.Push(r)
	case TypeNSEC, TypeNSEC3:
		s.Nxt = r
	default:
		s.RRs.Push(r)
	}
	z.Push(s)
}

// Push a new ZRRset to the zone
func (z Zone) Push(s *ZRRset) {
        // s can hold RRs, RRsigs or a Nxt
        name := ""
        i := 0
        switch {
        case len(s.RRs) != 0:
                name = s.RRs[0].Header().Name
	        i = intval(s.RRs[0].Header().Class, s.RRs[0].Header().Rrtype)
        case len(s.RRsigs) != 0:
                name = s.RRsigs[0].Header().Name
	        i = intval(s.RRsigs[0].Header().Class, s.RRsigs[0].Header().Rrtype)
        case s.Nxt != nil:
                name = s.Nxt.Header().Name
	        i = intval(s.Nxt.Header().Class, s.Nxt.Header().Rrtype)
        }
	if z[name] == nil {
		im := make(map[int]*ZRRset) // intmap
		im[i] = s
		z[name] = im
		return
	}
	im := z[name]
	im[i] = s
	return
}

// Lookup the RR in the zone, we are only looking at
// qname, qtype and qclass of the RR
// Considerations for wildcards
// Return NXDomain, Name error, wildcard?
// Casing!
func (z Zone) LookupRR(r RR) (*ZRRset, os.Error) {
	return z.lookup(r.Header().Name, r.Header().Class, r.Header().Rrtype)
}

func (z Zone) LookupQuestion(q Question) (*ZRRset, os.Error) {
	return z.lookup(q.Name, q.Qclass, q.Qtype)
}

func (z Zone) lookup(qname string, qclass, qtype uint16) (*ZRRset, os.Error) {
	i := intval(qclass, qtype)
	if im, ok := z[qname]; ok {
		// Have an im, intmap
		if s, ok := im[i]; ok {
			return s, nil
		}
		// Name found, class/type not found
		return nil, nil
	}
	return nil, nil
}

// Number in the second map denotes the class + type.
func intval(c, t uint16) int {
	return int(c)*_CLASS + int(t)
}
