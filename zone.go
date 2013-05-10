package dns

// A structure for handling zone data

import (
	"math/rand"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// TODO(mg): the memory footprint could be reduced when we would chop off the
// the zone's origin from every RR. However they are given to us as pointers
// and as such require copies when we fiddle with them...

// Zone represents a DNS zone. It's safe for concurrent use by
// multilpe goroutines.
type Zone struct {
	Origin       string               // Origin of the zone
	olen         int                  // Origin length
	olabels      []string             // Origin cut up in labels, just to speed up the isSubDomain method
	expired      bool                 // Slave zone is expired
	ModTime      time.Time            // When is the zone last modified
	Names        map[string]*ZoneData // Zone data, indexed by owner name
	*sortedNames                      // Sorted names for either NSEC or NSEC3
	*sync.RWMutex
	// The zone's security status, supported values are TypeNone for no DNSSEC,
	// TypeNSEC for an NSEC type zone and TypeNSEC3 for an NSEC3 signed zone.
	Security int
	// If not nil, this function is called after each modification.
	NotifyFunc func(inserted, deleted RR)
}

type sortedNames struct {
	// A sorted list of all names in the zone.
	nsecNames []string
	// A sorted list of all hashed names in the zone, the hash parameters are taken from the NSEC3PARAM
	// record located in the zone's apex.
	nsec3Names []string
}

// Used for nsec(3) bitmap sorting
type uint16Slice []uint16

func (p uint16Slice) Len() int           { return len(p) }
func (p uint16Slice) Less(i, j int) bool { return p[i] < p[j] }
func (p uint16Slice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

// SignatureConfig holds the parameters for zone (re)signing. This
// is copied from OpenDNSSEC. See:
// https://wiki.opendnssec.org/display/DOCS/kasp.xml
type SignatureConfig struct {
	// Validity period of the signatures, typically 2 to 4 weeks.
	Validity time.Duration
	// When the end of the validity approaches, how much time should remain
	// before we start to resign. Typical value is 3 days.
	Refresh time.Duration
	// Jitter is an random amount of time added or subtracted from the
	// expiration time to ensure not all signatures expire a the same time.
	// Typical value is 12 hours, which means the actual jitter value is
	// between -12..0..+12.
	Jitter time.Duration
	// InceptionOffset is subtracted from the inception time to ensure badly
	// calibrated clocks on the internet can still validate a signature.
	// Typical value is 300 seconds.
	InceptionOffset time.Duration
	// HonorSepFlag is a boolean which when try instructs the signer to use
	// a KSK/ZSK split and only sign the keyset with the KSK(s). If not
	// set all records are signed with all keys. If this flag is true and
	// a single KSK is used for signing, only the keyset is signed.
	HonorSepFlag bool
	// SignerRoutines specifies the number of signing goroutines, if not
	// set runtime.NumCPU() + 1 is used as the value.
	SignerRoutines int
	// The zone's SOA Minttl value must be used as the ttl on NSEC/NSEC3 records.
	Minttl uint32
}

func newSignatureConfig() *SignatureConfig {
	return &SignatureConfig{time.Duration(4*7*24) * time.Hour, time.Duration(3*24) * time.Hour, time.Duration(12) * time.Hour, time.Duration(300) * time.Second, true, runtime.NumCPU() + 1, 0}
}

// DefaultSignaturePolicy has the following values. Validity is 4 weeks,
// Refresh is set to 3 days, Jitter to 12 hours and InceptionOffset to 300 seconds.
// HonorSepFlag is set to true, SignerRoutines is set to runtime.NumCPU() + 1. The
// Minttl value is zero.
var DefaultSignatureConfig = newSignatureConfig()

// NewZone creates an initialized zone with Origin set to the lower cased origin.
func NewZone(origin string) *Zone {
	if origin == "" {
		origin = "."
	}
	if _, _, ok := IsDomainName(origin); !ok {
		return nil
	}
	z := new(Zone)
	z.Origin = Fqdn(strings.ToLower(origin))
	z.olen = len(z.Origin)
	z.olabels = SplitLabels(z.Origin)
	z.Names = make(map[string]*ZoneData)
	z.RWMutex = new(sync.RWMutex)
	z.ModTime = time.Now().UTC()
	z.sortedNames = &sortedNames{make([]string, 0), make([]string, 0)}
	return z
}

// In theory we can remove the ownernames from the RRs, because they are all the same,
// however, cutting the RR and possibly copying into a new structure requires memory too.
// For now: just leave the RRs as-is.

// ZoneData holds all the RRs for a specific owner name.
type ZoneData struct {
	RR        map[uint16][]RR     // Map of the RR type to the RR
	Signature map[uint16][]*RRSIG // DNSSEC signatures for the RRs, stored under type covered
	NonAuth   bool                // Always false, except for NSsets that differ from z.Origin
}

// NewZoneData creates a new zone data element.
func NewZoneData() *ZoneData {
	zd := new(ZoneData)
	zd.RR = make(map[uint16][]RR)
	zd.Signature = make(map[uint16][]*RRSIG)
	return zd
}

// String returns a string representation of a ZoneData. There is no
// String for the entire zone, because this will (most likely) take up
// a huge amount of memory.
func (zd *ZoneData) String() string {
	var (
		s string
		t uint16
	)
	// Make sure SOA is first
	// There is only one SOA, but it may have multiple sigs
	if soa, ok := zd.RR[TypeSOA]; ok {
		s += soa[0].String() + "\n"
		if _, ok := zd.Signature[TypeSOA]; ok {
			for _, sig := range zd.Signature[TypeSOA] {
				s += sig.String() + "\n"
			}
		}
	}

Types:
	for _, rrset := range zd.RR {
		for _, rr := range rrset {
			t = rr.Header().Rrtype
			if t == TypeSOA || t == TypeNSEC { // Done above or below
				continue Types
			}
			s += rr.String() + "\n"
		}
		if _, ok := zd.Signature[t]; ok {
			for _, rr := range zd.Signature[t] {
				s += rr.String() + "\n"
			}
		}
	}
	// Make sure NSEC is last
	// There is only one NSEC, but it may have multiple sigs
	if soa, ok := zd.RR[TypeNSEC]; ok {
		s += soa[0].String() + "\n"
		if _, ok := zd.Signature[TypeNSEC]; ok {
			for _, sig := range zd.Signature[TypeNSEC] {
				s += sig.String() + "\n"
			}
		}
	}
	return s
}

// Insert inserts the RR r into the zone.
func (z *Zone) Insert(r RR) error {
	z.Lock()
	defer z.Unlock()
	if !z.isSubDomain(r.Header().Name) {
		return &Error{Err: "out of zone data", Name: r.Header().Name}
	}
	z.ModTime = time.Now().UTC()
	zd, ok := z.Names[r.Header().Name]
	if !ok {
		zd = NewZoneData()
		switch t := r.Header().Rrtype; t {
		case TypeRRSIG:
			sigtype := r.(*RRSIG).TypeCovered
			zd.Signature[sigtype] = append(zd.Signature[sigtype], r.(*RRSIG))
		case TypeNS:
			// NS records with other names than z.Origin are non-auth
			if r.Header().Name != z.Origin {
				zd.NonAuth = true
			}
			fallthrough
		default:
			zd.RR[t] = append(zd.RR[t], r)
		}
		z.Names[r.Header().Name] = zd
		i := sort.SearchStrings(z.sortedNames.nsecNames, r.Header().Name)
		z.sortedNames.nsecNames = append(z.sortedNames.nsecNames, "")
		copy(z.sortedNames.nsecNames[i+1:], z.sortedNames.nsecNames[i:])
		z.sortedNames.nsecNames[i] = r.Header().Name
		return nil
	}
	// Name already there
	switch t := r.Header().Rrtype; t {
	case TypeRRSIG:
		sigtype := r.(*RRSIG).TypeCovered
		zd.Signature[sigtype] = append(zd.Signature[sigtype], r.(*RRSIG))
	case TypeNS:
		if r.Header().Name != z.Origin {
			zd.NonAuth = true
		}
		fallthrough
	default:
		zd.RR[t] = append(zd.RR[t], r)
	}
	return nil
}

// Remove removes the RR r from the zone. If the RR can not be found,
// this is a no-op.
func (z *Zone) Remove(r RR) error {
	z.Lock()
	defer z.Unlock()
	zd, ok := z.Names[r.Header().Name]
	if !ok {
		return nil
	}
	z.ModTime = time.Now().UTC()
	switch t := r.Header().Rrtype; t {
	case TypeRRSIG:
		sigtype := r.(*RRSIG).TypeCovered
		for i, zr := range zd.Signature[sigtype] {
			if r == zr {
				zd.Signature[sigtype] = append(zd.Signature[sigtype][:i], zd.Signature[sigtype][i+1:]...)
			}
		}
		if len(zd.Signature[sigtype]) == 0 {
			delete(zd.Signature, sigtype)
		}
	default:
		for i, zr := range zd.RR[t] {
			// Matching RR
			if r == zr {
				zd.RR[t] = append(zd.RR[t][:i], zd.RR[t][i+1:]...)
			}
		}
		if len(zd.RR[t]) == 0 {
			delete(zd.RR, t)
		}
	}
	if len(zd.RR) == 0 && len(zd.Signature) == 0 {
		// Entire node is empty, remove it from the Zone too
		delete(z.Names, r.Header().Name)
		i := sort.SearchStrings(z.sortedNames.nsecNames, r.Header().Name)
		// we actually removed something if we are here, so i must be something sensible
		copy(z.sortedNames.nsecNames[i:], z.sortedNames.nsecNames[i+1:])
		z.sortedNames.nsecNames[len(z.sortedNames.nsecNames)-1] = ""
		z.sortedNames.nsecNames = z.sortedNames.nsecNames[:len(z.sortedNames.nsecNames)-1]
	}
	return nil
}

// RemoveName removes all the RRs with ownername matching s from the zone. Typical use of this
// method is when processing a RemoveName dynamic update packet.
func (z *Zone) RemoveName(s string) error {
	z.Lock()
	defer z.Unlock()
	_, ok := z.Names[s]
	if !ok {
		return nil
	}
	z.ModTime = time.Now().UTC()
	delete(z.Names, s)
	i := sort.SearchStrings(z.sortedNames.nsecNames, s)
	copy(z.sortedNames.nsecNames[i:], z.sortedNames.nsecNames[i+1:])
	z.sortedNames.nsecNames[len(z.sortedNames.nsecNames)-1] = ""
	z.sortedNames.nsecNames = z.sortedNames.nsecNames[:len(z.sortedNames.nsecNames)-1]
	return nil
}

// RemoveRRset removes all the RRs with the ownername matching s and the type matching t from the zone.
// Typical use of this method is when processing a RemoveRRset dynamic update packet.
func (z *Zone) RemoveRRset(s string, t uint16) error {
	z.Lock()
	defer z.Unlock()
	zd, ok := z.Names[s]
	if !ok {
		return nil
	}
	z.ModTime = time.Now().UTC()
	switch t {
	case TypeRRSIG:
		// empty all signature maps
		for cover, _ := range zd.Signature {
			delete(zd.Signature, cover)
		}
	default:
		// empty all rr maps
		for t, _ := range zd.RR {
			delete(zd.RR, t)
		}
	}
	if len(zd.RR) == 0 && len(zd.Signature) == 0 {
		// Entire node is empty, remove it from the Zone too
		delete(z.Names, s)
		i := sort.SearchStrings(z.sortedNames.nsecNames, s)
		// we actually removed something if we are here, so i must be something sensible
		copy(z.sortedNames.nsecNames[i:], z.sortedNames.nsecNames[i+1:])
		z.sortedNames.nsecNames[len(z.sortedNames.nsecNames)-1] = ""
		z.sortedNames.nsecNames = z.sortedNames.nsecNames[:len(z.sortedNames.nsecNames)-1]
	}
	return nil
}

// Apex returns the zone's apex records (SOA, NS and possibly others). If the
// apex can not be found (thereby making it an illegal DNS zone) it returns nil.
// Apex is safe for concurrent use.
func (z *Zone) Apex() *ZoneData {
	z.RLock()
	defer z.RUnlock()
	apex, ok := z.Names[z.Origin]
	if !ok {
		return nil
	}
	return apex
}

// Find looks up the ownername s in the zone and returns the data or nil
// when nothing can be found. Find is safe for concurrent use.
func (z *Zone) Find(s string) *ZoneData {
	z.RLock()
	defer z.RUnlock()
	node, ok := z.Names[s]
	if !ok {
		return nil
	}
	return node
}

func (z *Zone) isSubDomain(child string) bool {
	return compareLabelsSlice(z.olabels, strings.ToLower(child)) == len(z.olabels)
}

// compareLabels behaves exactly as CompareLabels expect that l1 is already
// a tokenize (in labels) version of the domain name. This saves memory and is faster.
func compareLabelsSlice(l1 []string, s2 string) (n int) {
	l2 := SplitLabels(s2)

	x1 := len(l1) - 1
	x2 := len(l2) - 1
	for {
		if x1 < 0 || x2 < 0 {
			break
		}
		if l1[x1] == l2[x2] {
			n++
		} else {
			break
		}
		x1--
		x2--
	}
	return
}

// Sign (re)signs the zone z with the given keys.
// NSECs and RRSIGs are added as needed.
// The public keys themselves are not added to the zone.
// If config is nil DefaultSignatureConfig is used. The signatureConfig
// describes how the zone must be signed and if the SEP flag (for KSK)
// should be honored. If signatures approach their expriration time, they
// are refreshed with the current set of keys. Valid signatures are left alone.
//
// Basic use pattern for signing a zone with the default SignatureConfig:
//
//	// A single PublicKey/PrivateKey have been read from disk.
//	e := z.Sign(map[*dns.DNSKEY]dns.PrivateKey{pubkey.(*dns.DNSKEY): privkey}, nil)
//	if e != nil {
//		// signing error
//	}
//	// Admire your signed zone...
func (z *Zone) Sign(keys map[*DNSKEY]PrivateKey, config *SignatureConfig) error {
	z.Lock()
	z.ModTime = time.Now().UTC()
	defer z.Unlock()
	if config == nil {
		config = DefaultSignatureConfig
	}
	// Pre-calc the key tags
	keytags := make(map[*DNSKEY]uint16)
	for k, _ := range keys {
		keytags[k] = k.KeyTag()
	}

	errChan := make(chan error)
	zonChan := make(chan *ZoneData, config.SignerRoutines*2)

	// Start the signer goroutines
	wg := new(sync.WaitGroup)
	wg.Add(config.SignerRoutines)
	for i := 0; i < config.SignerRoutines; i++ {
		go signerRoutine(z, wg, keys, keytags, config, zonChan, errChan)
	}

	var err error
	apex := z.Apex()
	if apex == nil {
		return ErrSoa
	}
	config.Minttl = apex.RR[TypeSOA][0].(*SOA).Minttl
Sign:
	for name := range z.Names {
		select {
		case err = <-errChan:
			break Sign
		default:
			zonChan <- z.Names[name]
		}
	}
	close(zonChan)
	close(errChan)
	if err != nil {
		return err
	}
	wg.Wait()
	return nil
}

// Sign3 (re)signs the zone z with the given keys, NSEC3s and RRSIGs are
// added as needed. Bla bla Identical to zone.Sign.
func (z *Zone) Sign3(keys map[*DNSKEY]PrivateKey, config *SignatureConfig) error {
	return nil
}

// signerRoutine is a small helper routine to make the concurrent signing work.
func signerRoutine(z *Zone, wg *sync.WaitGroup, keys map[*DNSKEY]PrivateKey, keytags map[*DNSKEY]uint16, config *SignatureConfig, in chan *ZoneData, err chan error) {
	next := ""
	defer wg.Done()
	for {
		select {
		case node, ok := <-in:
			if !ok {
				return
			}
			name := ""
			for x := range node.RR {
				name = node.RR[x][0].Header().Name
				break
			}
			i := sort.SearchStrings(z.sortedNames.nsecNames, name)
			if z.sortedNames.nsecNames[i] == name {
				if i+1 > len(z.sortedNames.nsecNames) {
					next = z.Origin
				} else {
					next = z.sortedNames.nsecNames[i+1]
				}
			}
			e := node.Sign(next, keys, keytags, config)
			if e != nil {
				err <- e
				return
			}
		}
	}
}

// Sign signs a single ZoneData node.
// The caller must take care that the zone itself is also locked for writing.
// For a more complete description see zone.Sign.
// Note, because this method has no (direct)
// access to the zone's SOA record, the SOA's Minttl value should be set in *config.
func (node *ZoneData) Sign(next string, keys map[*DNSKEY]PrivateKey, keytags map[*DNSKEY]uint16, config *SignatureConfig) error {
	n, nsecok := node.RR[TypeNSEC]
	bitmap := []uint16{TypeNSEC, TypeRRSIG}
	bitmapEqual := true
	name := ""
	for t, _ := range node.RR {
		if name == "" {
			name = node.RR[t][0].Header().Name
		}
		if nsecok {
			// Check if the current (if available) nsec has these types too
			// Grr O(n^2)
			found := false
			for _, v := range n[0].(*NSEC).TypeBitMap {
				if v == t {
					found = true
					break
				}
				if v > t { // It is sorted, so by now we haven't found it
					found = false
					break
				}
			}
			if !found {
				bitmapEqual = false
			}
		}
		if t == TypeNSEC || t == TypeRRSIG {
			continue
		}
		bitmap = append(bitmap, t)

	}
	sort.Sort(uint16Slice(bitmap))

	if nsecok {
		// There is an NSEC, check if it still points to the correct next node.
		// Secondly the type bitmap may have changed.
		// TODO(mg): actually checked the types in the map
		if n[0].(*NSEC).NextDomain != next || !bitmapEqual {
			n[0].(*NSEC).NextDomain = next
			n[0].(*NSEC).TypeBitMap = bitmap
			node.Signature[TypeNSEC] = nil // drop all sigs
		}
	} else {
		// No NSEC at all, create one
		nsec := &NSEC{Hdr: RR_Header{name, TypeNSEC, ClassINET, config.Minttl, 0}, NextDomain: next}
		nsec.TypeBitMap = bitmap
		node.RR[TypeNSEC] = []RR{nsec}
		node.Signature[TypeNSEC] = nil // drop all sigs (just in case)
	}

	// Walk all keys, and check the sigs
	now := time.Now().UTC()
	for k, p := range keys {
		for t, rrset := range node.RR {
			if k.Flags&SEP == SEP {
				if _, ok := rrset[0].(*DNSKEY); !ok {
					// only sign keys with SEP keys
					continue
				}
			}
			if node.NonAuth == true {
				_, ok1 := rrset[0].(*DS)
				_, ok2 := rrset[0].(*NSEC)
				if !ok1 && !ok2 {
					continue
				}
			}

			j, q := signatures(node.Signature[t], keytags[k])
			if q == nil || now.Sub(uint32ToTime(q.Expiration)) < config.Refresh { // no there, are almost expired
				s := new(RRSIG)
				s.SignerName = k.Hdr.Name
				s.Hdr.Ttl = k.Hdr.Ttl
				s.Hdr.Class = ClassINET
				s.Algorithm = k.Algorithm
				s.KeyTag = keytags[k]
				s.Inception = timeToUint32(now.Add(-config.InceptionOffset))
				s.Expiration = timeToUint32(now.Add(jitterDuration(config.Jitter)).Add(config.Validity))
				e := s.Sign(p, rrset)
				if e != nil {
					return e
				}
				if q != nil {
					node.Signature[t][j] = s // replace the signature
				} else {
					node.Signature[t] = append(node.Signature[t], s) // add it
				}
			}
		}
	}
	// All signatures have been made are refreshed. Now check the all signatures for expiraton
	for i, s := range node.Signature {
		// s is another slice
		for i1, s1 := range s {
			if now.Sub(uint32ToTime(s1.Expiration)) < config.Refresh {
				// can only happen if made with an unknown key, drop the sig
				node.Signature[i] = append(node.Signature[i][:i1], node.Signature[i][i1+1:]...)
			}
		}
	}
	return nil
}

// Return the signature for the typecovered and made with the keytag. It
// returns the index of the RRSIG and the RRSIG itself.
func signatures(signatures []*RRSIG, keytag uint16) (int, *RRSIG) {
	for i, s := range signatures {
		if s.KeyTag == keytag {
			return i, s
		}
	}
	return 0, nil
}

// timeToUint32 translates a time.Time to a 32 bit value which
// can be used as the RRSIG's inception or expiration times.
func timeToUint32(t time.Time) uint32 {
	mod := (t.Unix() / year68) - 1
	if mod < 0 {
		mod = 0
	}
	return uint32(t.Unix() - (mod * year68))
}

// uint32ToTime translates a uint32 to a time.Time
func uint32ToTime(t uint32) time.Time {
	// uint32 to duration and then add it to epoch(0)
	mod := (time.Now().Unix() / year68) - 1
	if mod < 0 {
		mod = 0
	}
	duration := time.Duration((mod * year68) * int64(t))
	return time.Unix(0, 0).Add(duration)
}

// jitterTime returns a random +/- jitter
func jitterDuration(d time.Duration) time.Duration {
	jitter := rand.Intn(int(d))
	if rand.Intn(1) == 1 {
		return time.Duration(jitter)
	}
	return -time.Duration(jitter)
}
