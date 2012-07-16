package dns

// A structure for handling zone data

import (
	"radix"
)

// Zone represents a DNS zone. 
type Zone struct {
	Name         string // Name of the zone
	*radix.Radix        // Zone data

	// soa parameters in here TODO(mg)
}

// ZoneData holds all the RR belonging to Name.
// TODO(mg): uitbreiden
type ZoneData struct {
	Name       string          // Domain name for this node
	RR         map[uint16][]RR // Map of the RR type to the RR
	Signatures []*RR_RRSIG     // DNSSEC signatures
	Glue       bool            // True if the A and AAAA record are glue
}

// New ...
func NewZone(name string) *Zone {
	z := new(Zone)
	z.Name = name
	z.Radix = radix.New()
	return z
}

// Insert inserts an RR into the zone. Overwrites.
func (z *Zone) Insert(r RR) {
	zd := z.Radix.Find(r.Header().Name)
	if zd == nil {
		zd := new(ZoneData)
		zd.Name = r.Header().Name
		zd.RR = make(map[uint16][]RR)
		zd.Signatures = make([]*RR_RRSIG, 0)
		switch t := r.Header().Rrtype; t {
		case TypeRRSIG:
			zd.Signatures = append(zd.Signatures, r.(*RR_RRSIG))
		default:
			zd.RR[t] = append(zd.RR[t], r)
			glueCheck(r)
		}
		z.Radix.Insert(r.Header().Name, zd)
		return
	}
	switch t := r.Header().Rrtype; t {
	case TypeRRSIG:
		zd.Value.(*ZoneData).Signatures = append(zd.Value.(*ZoneData).Signatures, r.(*RR_RRSIG))
	default:
		zd.Value.(*ZoneData).RR[t] = append(zd.Value.(*ZoneData).RR[t], r)
	}
	return
}

func glueCheck(r RR) {
	if n, ok := r.(*RR_NS); ok {
		// Check if glue would be needed
		if CompareLabels(r.Header().Name, n.Ns) == LenLabels(r.Header().Name) {
			println("glue needed?", r.Header().Name, n.Ns)
		}
	}
}

func (z *Zone) Remove(r RR) {

}
