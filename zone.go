package dns

// A structure for handling zone data

import (
	"github.com/miekg/radix"
	"sort"
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
	// SOA MINTTL value
	minttl uint32
}

func newSignatureConfig() *SignatureConfig {
	return &SignatureConfig{time.Duration(4*7*24) * time.Hour, time.Duration(3*24) * time.Hour, time.Duration(12) * time.Hour, time.Duration(300) * time.Second, 0}
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
	mutex      *sync.RWMutex          // For locking
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

// String returns a string representation of a ZoneData. There is no
// String for the entire zone, because this will (most likely) take up
// a huge amount of memory. Basic use pattern for printing an entire
// zone:
//
//	// z contains the zone
//	z.Radix.Do(func(i interface{}) {
//		fmt.Printf("%s", i.(*dns.ZoneData).String()) })
func (zd *ZoneData) String() string {
	var (
		s string
		t uint16
	)
	// Make sure SOA is first
	// There is only one SOA, but it may have multiple sigs
	if soa, ok := zd.RR[TypeSOA]; ok {
		s += soa[0].String() + "\n"
		if _, ok := zd.Signatures[TypeSOA]; ok {
			for _, sig := range zd.Signatures[TypeSOA] {
				s += sig.String() + "\n"
			}
		}
	}

Types:
	for _, rrset := range zd.RR {
		for _, rr := range rrset {
			t = rr.Header().Rrtype
			if t == TypeSOA { // Done above
				continue Types
			}
			s += rr.String() + "\n"
		}
		if _, ok := zd.Signatures[t]; ok {
			for _, rr := range zd.Signatures[t] {
				s += rr.String() + "\n"
			}
		}
	}
	return s
}

// Insert inserts an RR into the zone. There is no check for duplicate data, although
// Remove will remove all duplicates.
func (z *Zone) Insert(r RR) error {
	if !IsSubDomain(z.Origin, r.Header().Name) {
		return &Error{Err: "out of zone data", Name: r.Header().Name}
	}

	// TODO(mg): quick check for doubles?
	key := toRadixName(r.Header().Name)
	z.mutex.Lock()
	zd, exact := z.Radix.Find(key)
	if !exact {
		// Not an exact match, so insert new value
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
	zd, exact := z.Radix.Find(key)
	if !exact {
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
// data and true when an exact match is found. If an exact find isn't
// possible the first parent node with a non-nil Value is returned and
// the boolean is false.
func (z *Zone) Find(s string) (node *ZoneData, exact bool) {
	z.mutex.RLock()
	defer z.mutex.RUnlock()
	n, e := z.Radix.Find(toRadixName(s))
	if n == nil {
		return nil, false
	}
	node = n.Value.(*ZoneData)
	exact = e
	return
}

// FindAndNext looks up the ownername s and its successor. It works
// just like Find.
func (z *Zone) FindAndNext(s string) (node, next *ZoneData, exact bool) {
	z.mutex.RLock()
	defer z.mutex.RUnlock()
	n, e := z.Radix.Find(toRadixName(s))
	if n == nil {
		return nil, nil, false
	}
	node = n.Value.(*ZoneData)
	next = n.Next().Value.(*ZoneData) // There is always a next
	exact = e
	return
}

// FindFunc works like Find, but the function f is executed on
// each node which has a non-nil Value during the tree traversal.
// If f returns true, that node is returned.
func (z *Zone) FindFunc(s string, f func(interface{}) bool) (*ZoneData, bool, bool) {
	z.mutex.RLock()
	defer z.mutex.RUnlock()
	zd, e, b := z.Radix.FindFunc(toRadixName(s), f)
	if zd == nil {
		return nil, false, false
	}
	return zd.Value.(*ZoneData), e, b
}

// Sign (re)signes the zone z with the given keys, it knows about ZSKs and KSKs.
// NSECs and RRSIGs are added as needed. The public keys themselves are not added
// to the zone.
// If config is nil DefaultSignatureConfig is used.
func (z *Zone) Sign(keys map[*RR_DNSKEY]PrivateKey, config *SignatureConfig) error {
	// TODO(mg): Write lock
	if config == nil {
		config = DefaultSignatureConfig
	}
	// Pre-calc the key tag
	keytags := make(map[*RR_DNSKEY]uint16)
	for k, _ := range keys {
		keytags[k] = k.KeyTag()
	}
	apex, next, _ := z.FindAndNext(z.Origin)

	// TODO(mg): check if it exissts
	config.minttl = apex.RR[TypeSOA][0].(*RR_SOA).Minttl
	signZoneData(apex, next, keys, keytags, config)
	return nil
}

// Sign each ZoneData in place.
// TODO(mg): assume not signed
func signZoneData(node, next *ZoneData, keys map[*RR_DNSKEY]PrivateKey, keytags map[*RR_DNSKEY]uint16, config *SignatureConfig) {
	nsec := new(RR_NSEC)
	nsec.Hdr.Rrtype = TypeNSEC
	nsec.Hdr.Ttl = 3600 // Must be SOA Min TTL
	nsec.Hdr.Name = node.Name
	nsec.NextDomain = next.Name // Only thing I need from next, actually
	nsec.Hdr.Class = ClassINET

	if node.NonAuth == true {
		// NSEC needed. Don't know. TODO(mg)
		for t, _ := range node.RR {
			nsec.TypeBitMap = append(nsec.TypeBitMap, t)
		}
		sort.Sort(uint16Slice(nsec.TypeBitMap))
		node.RR[TypeNSEC] = []RR{nsec}
		for k, p := range keys {
			s := new(RR_RRSIG)
			s.SignerName = k.Hdr.Name
			s.Hdr.Ttl = k.Hdr.Ttl
			s.Algorithm = k.Algorithm
			s.KeyTag = keytags[k]
			s.Inception = 0 // TODO(mg)
			s.Expiration = 0
			s.Sign(p, []RR{nsec}) // discard error, TODO(mg)
			node.Signatures[TypeNSEC] = append(node.Signatures[TypeNSEC], s)
		}
		return
	}
	for k, p := range keys {
		for t, rrset := range node.RR {
			s := new(RR_RRSIG)
			s.SignerName = k.Hdr.Name
			s.Hdr.Ttl = k.Hdr.Ttl
			s.Hdr.Class = ClassINET
			s.Algorithm = k.Algorithm
			s.KeyTag = keytags[k]
			s.Inception = 0 // TODO(mg)
			s.Expiration = 0
			s.Sign(p, rrset) // discard error, TODO(mg)
			node.Signatures[t] = append(node.Signatures[t], s)
			nsec.TypeBitMap = append(nsec.TypeBitMap, t)
		}
		sort.Sort(uint16Slice(nsec.TypeBitMap))
		node.RR[TypeNSEC] = []RR{nsec}
		// NSEC
		s := new(RR_RRSIG)
		s.SignerName = k.Hdr.Name
		s.Hdr.Ttl = k.Hdr.Ttl
		s.Algorithm = k.Algorithm
		s.KeyTag = keytags[k]
		s.Inception = 0 // TODO(mg)
		s.Expiration = 0
		s.Sign(p, []RR{nsec}) // discard error, TODO(mg)
		node.Signatures[TypeNSEC] = append(node.Signatures[TypeNSEC], s)
	}
}

type uint16Slice []uint16

func (p uint16Slice) Len() int           { return len(p) }
func (p uint16Slice) Less(i, j int) bool { return p[i] < p[j] }
func (p uint16Slice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
