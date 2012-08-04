package dns

// A structure for handling zone data

import (
	"radix"
	"strings"
)

// Zone represents a DNS zone. 
type Zone struct {
	Origin       string // Origin of the zone
	*radix.Radix        // Zone data
}

// ZoneData holds all the RRs having their ownername equal to Name.
type ZoneData struct {
	Name       string               // Domain name for this node
	RR         map[uint16][]RR      // Map of the RR type to the RR
	Signatures map[uint16][]*RR_RRSIG // DNSSEC signatures for the RRs, stored under type covered
	// Always false, except for NSsets that differ from z.Origin
	NonAuth bool
}

// toRadixName reverses a domainname so that when we store it in the radix tree
// we preserve the nsec ordering of the zone (this idea was stolen from NSD).
// each label is also lowercased.
func toRadixName(d string) string {
	s := ""
	for _, l := range SplitLabels(d) {
		s = strings.ToLower(l) + "." + s
	}
	return s
}

// NewZone creates an initialized zone with Origin set to origin.
func NewZone(origin string) *Zone {
	if origin == "" {
		origin = "."
	}
	if _, _, ok := IsDomainName(origin); !ok {
		return nil
	}
	z := new(Zone)
	z.Origin = Fqdn(origin)
	z.Radix = radix.New()
	return z
}

// Insert inserts an RR into the zone. Duplicate data overwrites the old data.
func (z *Zone) Insert(r RR) error {
	if !IsSubDomain(r.Header().Name, z.Origin) {
		return &Error{Err: "out of zone data", Name: r.Header().Name}
	}

	key := toRadixName(r.Header().Name)
	zd := z.Radix.Find(key)
	if zd == nil {
		zd := new(ZoneData)
		zd.Name = r.Header().Name
		zd.RR = make(map[uint16][]RR)
		zd.Signatures = make(map[uint16][]*RR_RRSIG)
		switch t := r.Header().Rrtype; t {
		case TypeRRSIG:
			sigtype := r.(*RR_RRSIG).TypeCovered
			zd.Signatures[sigtype] = append(zd.Signatures[sigtype], r.(*RR_RRSIG))
		case TypeNS:
			// NS records with other names than z.Origin are non-auth
			if r.Header().Name != z.Origin {
				zd.NonAuth = true
			}
			fallthrough
		default:
			zd.RR[t] = append(zd.RR[t], r)
		}
		z.Radix.Insert(key, zd)
		return nil
	}
	// Name already there
	switch t := r.Header().Rrtype; t {
	case TypeRRSIG:
		sigtype := r.(*RR_RRSIG).TypeCovered
		zd.Value.(*ZoneData).Signatures[sigtype] = append(zd.Value.(*ZoneData).Signatures[sigtype], r.(*RR_RRSIG))
	case TypeNS:
		if r.Header().Name != z.Origin {
			zd.Value.(*ZoneData).NonAuth = true
		}
		fallthrough
	default:
		zd.Value.(*ZoneData).RR[t] = append(zd.Value.(*ZoneData).RR[t], r)
	}
	return nil
}

// RemoveName removeRRset ??
func (z *Zone) Remove(r RR) error {
	return nil
}

// Find wraps radix.Find. 
func (z *Zone) Find(s string) *ZoneData {
	zd := z.Radix.Find(toRadixName(s))
	if zd == nil {
		return nil
	}
	return zd.Value.(*ZoneData)
}

// Predecessor wraps radix.Predecessor.
func (z *Zone) Predecessor(s string) *ZoneData {
	zd := z.Radix.Predecessor(toRadixName(s))
	if zd == nil {
		return nil
	}
	return zd.Value.(*ZoneData)
}
