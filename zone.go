// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"os"
	"sort"
	"strings"
)

const _CLASS = 2 << 16

// ZRRset is a structure that keeps several items from
// a zone file together. 
type ZRRset struct {
	RRs    RRset // the RRset for this type and name
	RRsigs RRset // the RRSIGs belonging to this RRset (if any)
	Nxt    RR    // the NSEC or NSEC3 for this name
	Glue   bool  // when this RRset is glue, set to true
}

// NewZRRset returns a pointer to a new ZRRset.
func NewZRRset() *ZRRset {
	s := new(ZRRset)
	s.RRs = NewRRset()
	s.RRsigs = NewRRset()
	return s
}

// Zone implements the concept of RFC 1035 master zone files.
// We store the zone contents in a map where the ownername is
// the key. In that map we have another map with integers 
// (class * _CLASS + type) that has the ZRRset:
// map[<ownername>] -> map[<int>] -> ZRRset
type Zone struct {
	Zone map[string]map[int]*ZRRset // the contents of the zone
	Nxt  *QnameString               // sorted list of owernames in the zone
}

// NewZone returns a new *Zone
func NewZone() *Zone {
	z := new(Zone)
	z.Zone = make(map[string]map[int]*ZRRset)
	z.Nxt = NewQnameString()
	return z
}

// Pop returns the last pushed ZRRset from z.
// Get the first value 
func (z *Zone) Pop() *ZRRset {
	for _, v := range z.Zone {
		for _, v1 := range v {
			return v1
		}
	}
	return nil
}

// PopRR returns the last RR pushed from z.
func (z *Zone) PopRR() RR {
	s := z.Pop()
	if s == nil {
		return nil
	}
	switch {
	case len(s.RRs) != 0:
		return s.RRs.Pop()
	case len(s.RRsigs) != 0:
		return s.RRsigs.Pop()
	case s.Nxt != nil:
		return s.Nxt
	}
	panic("not reached")
	return nil
}

// Len returns the number of RRs in z.
func (z *Zone) Len() int {
	i := 0
	for _, im := range z.Zone {
		for _, s := range im {
			i += len(s.RRs) + len(s.RRsigs)
			if s.Nxt != nil {
				i++
			}
		}
	}
	return i
}

func (z *Zone) String() string {
	s := ""
	for _, im := range z.Zone {
		for _, s1 := range im {
			s += s1.RRs.String()
			s += s1.RRsigs.String()
			if s1.Nxt != nil {
				s += s1.Nxt.String() + "\n"
			}
		}
	}
	return s
}

// PushRR adds a new RR to the zone. 
func (z *Zone) PushRR(r RR) {
	s, _ := z.LookupRR(r)
	if s == nil {
		s = NewZRRset()
	}
	// Add to the sorted ownernames list
	SortInsert(z.Nxt, r.Header().Name)

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

// Push adds a new ZRRset to the zone.
func (z *Zone) Push(s *ZRRset) {
	// s can hold RRs, RRsigs or a Nxt
	name := ""
	i := 0
	switch {
	case len(s.RRs) != 0:
		name = s.RRs[0].Header().Name
		i = intval(s.RRs[0].Header().Class, s.RRs[0].Header().Rrtype)
	case len(s.RRsigs) != 0:
		name = s.RRsigs[0].Header().Name
		i = intval(s.RRsigs[0].Header().Class, s.RRsigs[0].(*RR_RRSIG).TypeCovered)
	case s.Nxt != nil:
		name = s.Nxt.Header().Name
		i = intval(s.Nxt.Header().Class, s.Nxt.Header().Rrtype)
	}
	if z.Zone[name] == nil {
		im := make(map[int]*ZRRset) // intmap
		im[i] = s
		z.Zone[name] = im
		return
	}
	im := z.Zone[name]
	im[i] = s
	return
}

// Lookup the RR in the zone, we are only looking at
// qname, qtype and qclass of the RR
// Considerations for wildcards
// Return NXDomain, Name error, wildcard?
// Casing!
func (z *Zone) LookupRR(r RR) (*ZRRset, os.Error) {
	if r.Header().Rrtype == TypeRRSIG {
		return z.LookupName(r.Header().Name, r.Header().Class, r.(*RR_RRSIG).TypeCovered)
	}
	return z.LookupName(r.Header().Name, r.Header().Class, r.Header().Rrtype)
}

func (z *Zone) LookupQuestion(q Question) (*ZRRset, os.Error) {
	// Impossible to look for an typecovered in a question, because the rdata is
	// not there.
	return z.LookupName(q.Name, q.Qclass, q.Qtype)
}

func (z *Zone) LookupName(qname string, qclass, qtype uint16) (*ZRRset, os.Error) {
	i := intval(qclass, qtype)
	if im, ok := z.Zone[strings.ToLower(qname)]; ok {
		// Have an im, intmap
		if s, ok := im[i]; ok {
			return s, nil
		}
		// Wildcard 'n stuff
		return nil, ErrName
	}
	return nil, nil
}

// Number in the second map denotes the class + type.
func intval(c, t uint16) int {
	return int(c)*_CLASS + int(t)
}

// SortInsert insert the string s in the already sorted
// vector p. If s is already present it is not inserted again.
func SortInsert(p *QnameString, s string) {
	i := sort.Search(len(*p), func(i int) bool { return (*p)[i] >= s })
	if i < len(*p) && (*p)[i] == s {
		// element already there
		return
	}
	p.Insert(i, s)
}

// Search searches the sorted vector p using binary search. If
// the element s can not be found, the previous element is returned.
func SortSearch(p *QnameString, s string) string {
	i := sort.Search(len(*p), func(i int) bool { return (*p)[i] >= s })
	// with zones there must always be one before
	if (*p)[i] == s {
		return s
	}
	if i > 0 {
		i--
	}
	return (*p)[i]
}
