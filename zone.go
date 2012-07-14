package dns

// A structure for handling zone data

import (
	"github.com/petar/GoLLRB/llrb"
)

type Zone struct {
	Name       string // Name of the zone
	*llrb.Tree        // Zone data
}

type ZoneData struct {
	Name       string                 // Domain name for this node
	RR         map[uint16][]RR        // Map ...
	Signatures map[uint16][]*RR_RRSIG // DNSSEC signatures
	Glue       bool                   // True if the A and AAAA record are glue
}

func lessZone(a, b interface{}) bool { return a.(string) < b.(string) }

// New ...
func New(name string) *Zone {
	z := new(Zone)
	z.Name = name
	z.Tree = llrb.New(lessZone)
	return z
}

func (z *Zone) Insert(r RR) {
	zd := z.Tree.Get(r.Header().Name)
}

func (z *Zone) Remove(r RR) {

}
