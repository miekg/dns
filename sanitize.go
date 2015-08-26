package dns

import "strings"

// Dedup removes identical RRs from rrs. It preserves the original ordering.
// The lowest TTL of any duplicates is used in the remaining one.
//
// TODO(miek): This function will be extended to also look for CNAMEs and DNAMEs.
// if found, it will prune rrs from the "other data" that can exist. Example:
// if it finds a: a.miek.nl. CNAME foo, all other RRs with the ownername a.miek.nl.
// will be removed. When a DNAME is found all RRs with an ownername below that of
// the DNAME will be removed.
func Dedup(rrs []RR) []RR {
	m := make(map[string]RR)
	keys := make([]string, 0, len(rrs))

	// Save possible cname and dname domainnames. Currently a slice, don't
	// expect millions here..
	cname := []string{}
	dname := []string{}

	for _, r := range rrs {
		key, end := normalizedString(r)
		keys = append(keys, key)
		if _, ok := m[key]; ok {
			// Shortest TTL wins.
			if m[key].Header().Ttl > r.Header().Ttl {
				m[key].Header().Ttl = r.Header().Ttl
			}
			continue
		}

		if r.Header().Rrtype == TypeCNAME {
			// we do end+3 here, so we capture the full domain name *and*
			// the class field which mnemonic is always two chars.
			cname = append(cname, key[:end+3])

		}
		if r.Header().Rrtype == TypeDNAME {
			dname = append(dname, key[:end+3])
		}

		m[key] = r
	}
	// If the length of the result map equals the amount of RRs we got,
	// it means they were all different. We can then just return the original rrset.
	// We can only do this when we haven't found a CNAME or DNAME.
	if len(m) == len(rrs) && len(cname) == 0 && len(dname) == 0 {
		return rrs
	}

	ret := make([]RR, 0, len(rrs))
	for i, r := range rrs {
		// If keys[i] lives in the map, we should copy it and remove
		// it from the map.
		if _, ok := m[keys[i]]; ok {
			if needsDeletion(r, keys[i], cname, dname) {
				// It the RR is masked by an CNAME or DNAME, we only
				// delete it from the map, but don't copy it.
				delete(m, keys[i])
				continue
			}

			delete(m, keys[i])
			ret = append(ret, r)
		}

		if len(m) == 0 {
			break
		}
	}

	return ret
}

// normalizedString returns a normalized string from r. The TTL
// is removed and the domain name is lowercased. The returned integer
// is the index where the domain name ends + 1.
func normalizedString(r RR) (string, int) {
	// A string Go DNS makes has: domainname<TAB>TTL<TAB>...
	b := []byte(r.String())

	// find the first non-escaped tab, then another, so we capture
	// where the TTL lives.
	esc := false
	ttlStart, ttlEnd := 0, 0
	for i, c := range b {
		if c == '\\' {
			esc = true
			continue
		}
		if esc {
			esc = false
			continue
		}
		if c == '\t' {
			if ttlStart == 0 {
				ttlStart = i
				continue
			}
			if ttlEnd == 0 {
				ttlEnd = i
				break
			}
		}
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}

	// remove TTL.
	copy(b[ttlStart:], b[ttlEnd:])
	cut := ttlEnd - ttlStart
	// ttlStart + 3 puts us on the start of the rdata
	return string(b[:len(b)-cut]), ttlStart
}

// needsDeletion checks if the RR is masked by either a CNAME or a DNAME.
// If so it return true.
func needsDeletion(r RR, s string, cname, dname []string) bool {
	// For CNAME we can do strings.HasPrefix with s.
	// For DNAME we can do strings.Contains with s.
	// Either signals a removal of this RR.
	for _, c := range cname {
		if strings.HasPrefix(s, c) {
			if r.Header().Rrtype == TypeCNAME {
				// don't delete yourself
				continue
			}
			return true
		}
	}
	for _, d := range dname {
		if strings.Contains(s, d) {
			if r.Header().Rrtype == TypeDNAME && strings.HasPrefix(s, d) {
				// don't delete yourself
				continue
			}
			return true
		}
	}
	return false
}
