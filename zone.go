package dns

// A structure for handling zone data

import (
	"github.com/miekg/radix"
	"strings"
	"sync"
	"time"
)

// Zone represents a DNS zone. It's safe for concurrent use by 
// multilpe goroutines.
type Zone struct {
	Origin       string // Origin of the zone
	Wildcard     int    // Whenever we see a wildcard name, this is incremented
	*radix.Radix        // Zone data
	mutex        *sync.RWMutex
	// timemodified?
	expired bool // Slave zone is expired
}

// SignatureConfig holds the parameters for zone (re)signing. This 
// is copied from OpenDNSSEC. See:
// https://wiki.opendnssec.org/display/DOCS/kasp.xml
type SignatureConfig struct {
	// Validity period of the signatures, typically 2 to 4 weeks.
	Validity time.Duration
	// When the end of the validity approaches, how much time should remain
	// before we start to resign. Typical value is 3 days.
	Refresh time.Duration
	// Jitter is an amount of time added or subtracted from the 
	// expiration time to ensure not all signatures expire a the same time.
	// Typical value is 12 hours.
	Jitter time.Duration
	// InceptionOffset is subtracted from the inception time to ensure badly
	// calibrated clocks on the internet can still validate a signature.
	// Typical value is 300 seconds.
	InceptionOffset time.Duration
}

func newSignatureConfig() *SignatureConfig {
	return &SignatureConfig{time.Duration(4*7*24) * time.Hour, time.Duration(3*24) * time.Hour, time.Duration(12) * time.Hour, time.Duration(300) * time.Second}
}

// DefaultSignaturePolicy has the following values. Validity is 4 weeks, 
// Refresh is set to 3 days, Jitter to 12 hours and InceptionOffset to 300 seconds.
var DefaultSignatureConfig = newSignatureConfig()

// NewZone creates an initialized zone with Origin set to origin.
func NewZone(origin string) *Zone {
	if origin == "" {
		origin = "."
	}
	if _, _, ok := IsDomainName(origin); !ok {
		return nil
	}
	z := new(Zone)
	z.mutex = new(sync.RWMutex)
	z.Origin = Fqdn(origin)
	z.Radix = radix.New()
	return z
}

// ZoneData holds all the RRs having their owner name equal to Name.
type ZoneData struct {
	Name       string                 // Domain name for this node
	RR         map[uint16][]RR        // Map of the RR type to the RR
	Signatures map[uint16][]*RR_RRSIG // DNSSEC signatures for the RRs, stored under type covered
	NonAuth    bool                   // Always false, except for NSsets that differ from z.Origin
	mutex      *sync.RWMutex
}

// newZoneData creates a new zone data element
func newZoneData(s string) *ZoneData {
	zd := new(ZoneData)
	zd.Name = s
	zd.RR = make(map[uint16][]RR)
	zd.Signatures = make(map[uint16][]*RR_RRSIG)
	zd.mutex = new(sync.RWMutex)
	return zd
}

// toRadixName reverses a domain name so that when we store it in the radix tree
// we preserve the nsec ordering of the zone (this idea was stolen from NSD).
// each label is also lowercased.
func toRadixName(d string) string {
	if d == "." {
		return "."
	}
	s := ""
	for _, l := range SplitLabels(d) {
		if s == "" {
			s = strings.ToLower(l) + s
			continue
		}
		s = strings.ToLower(l) + "." + s
	}
	return s
}

func (z *Zone) String() string {
	return z.Radix.String()
}

// Insert inserts an RR into the zone. There is no check for duplicate data, although
// Remove will remove all duplicates.
func (z *Zone) Insert(r RR) error {
	if !IsSubDomain(z.Origin, r.Header().Name) {
		return &Error{Err: "out of zone data", Name: r.Header().Name}
	}

	// TODO(mg): quick check for doubles
	key := toRadixName(r.Header().Name)
	z.mutex.Lock()
	zd := z.Radix.Find(key)
	if zd == nil {
		defer z.mutex.Unlock()
		// Check if it's a wildcard name
		if len(r.Header().Name) > 1 && r.Header().Name[0] == '*' && r.Header().Name[1] == '.' {
			z.Wildcard++
		}
		zd := newZoneData(r.Header().Name)
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
	z.mutex.Unlock()
	zd.Value.(*ZoneData).mutex.Lock()
	defer zd.Value.(*ZoneData).mutex.Unlock()
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

// Remove removes the RR r from the zone. If the RR can not be found,
// this is a no-op.
func (z *Zone) Remove(r RR) error {
	key := toRadixName(r.Header().Name)
	z.mutex.Lock()
	zd := z.Radix.Find(key)
	if zd == nil {
		defer z.mutex.Unlock()
		return nil
	}
	z.mutex.Unlock()
	zd.Value.(*ZoneData).mutex.Lock()
	defer zd.Value.(*ZoneData).mutex.Unlock()
	remove := false
	switch t := r.Header().Rrtype; t {
	case TypeRRSIG:
		sigtype := r.(*RR_RRSIG).TypeCovered
		for i, zr := range zd.Value.(*ZoneData).RR[sigtype] {
			if r == zr {
				zd.Value.(*ZoneData).RR[sigtype] = append(zd.Value.(*ZoneData).RR[sigtype][:i], zd.Value.(*ZoneData).RR[sigtype][i+1:]...)
				remove = true
			}
		}
	default:
		for i, zr := range zd.Value.(*ZoneData).RR[t] {
			if r == zr {
				zd.Value.(*ZoneData).RR[t] = append(zd.Value.(*ZoneData).RR[t][:i], zd.Value.(*ZoneData).RR[t][i+1:]...)
				remove = true
			}
		}
	}
	if remove && len(r.Header().Name) > 1 && r.Header().Name[0] == '*' && r.Header().Name[1] == '.' {
		z.Wildcard--
		if z.Wildcard < 0 {
			z.Wildcard = 0
		}
	}
	// TODO(mg): what to do if the whole structure is empty? Set it to nil?
	return nil
}

// Find looks up the ownername s in the zone and returns the
// data when found or nil when nothing is found.
func (z *Zone) Find(s string) *ZoneData {
	z.mutex.RLock()
	defer z.mutex.RUnlock()
	zd := z.Radix.Find(toRadixName(s))
	if zd == nil {
		return nil
	}
	return zd.Value.(*ZoneData)
}

// Predecessor searches the zone for a name shorter than s.
func (z *Zone) Predecessor(s string) *ZoneData {
	z.mutex.RLock()
	defer z.mutex.RUnlock()
	zd := z.Radix.Predecessor(toRadixName(s))
	if zd == nil {
		return nil
	}
	return zd.Value.(*ZoneData)
}

// Sign (re)signes the zone z. It adds keys to the zone (if not already there)
// and signs the keys with the KSKs and the rest of the zone with the ZSKs. 
// NSEC is used for authenticated denial 
// of existence. If config is nil DefaultSignatureConfig is used.
// TODO(mg): allow interaction with hsm
func (z *Zone) Sign(keys []*RR_DNSKEY, privkeys []PrivateKey, config *SignatureConfig) error {
	if config == nil {
		config = DefaultSignatureConfig
	}
	// TODO(mg): concurrently walk the zone and sign the rrsets
	// TODO(mg): nsec, or next pointer. Need to be a single tree-op

	return nil
}

// Sign each ZoneData in place.
// TODO(mg): assume not signed
func signZoneData(zd *ZoneData, privkeys []PrivateKey, signername string, config *SignatureConfig) {
	if zd.NonAuth == true {
		return
	}
	//s := new(RR_RRSIG)
	// signername

}
