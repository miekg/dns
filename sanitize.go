package dns

// Dedup removes identical RRs from rrs. It preserves the original ordering.
// The lowest TTL of any duplicates is used in the remaining one.
//
// TODO(miek): This function will be extended to also look for CNAMEs and DNAMEs.
// if found, it will prune rrs from the "other data" that can exist. Example:
// if it finds a: a.miek.nl. CNAME foo, all other RRs with the ownername a.miek.nl.
// will be removed.
func Dedup(rrs []RR) []RR {
	m := make(map[string]RR)
	keys := make([]string, 0, len(rrs))

	for _, r := range rrs {
		key := normalizedString(r)
		keys = append(keys, key)
		if _, ok := m[key]; ok {
			// Shortest TTL wins.
			if m[key].Header().Ttl > r.Header().Ttl {
				m[key].Header().Ttl = r.Header().Ttl
			}
			continue
		}
		m[key] = r
	}
	// If the length of the result map equals the amount of RRs we got,
	// it means they were all different. We can then just return the original rrset.
	if len(m) == len(rrs) {
		return rrs
	}
	var i = 0
	for i, _ = range rrs {
		if len(m) == 0 {
			break
		}
		// We saved the key for each RR.
		delete(m, keys[i])
	}
	return rrs[:i]
}

// normalizedString returns a normalized string from r. The TTL
// is removed and the domain name is lowercased.
func normalizedString(r RR) string {
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
	return string(b[:len(b)-cut])
}
