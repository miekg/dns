package dns

// Dedup removes identical RRs from rrs. It preserves the original ordering.
// The lowest TTL of any duplicates is used in the remaining one.
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

	ret := make([]RR, 0, len(rrs))
	for i, r := range rrs {
		// If keys[i] lives in the map, we should copy and remove it.
		if _, ok := m[keys[i]]; ok {
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
// is removed and the domain name is lowercased. We go from this:
// DomainName<TAB>TTL<TAB>CLASS<TAB>TYPE<TAB>RDATA to:
// lowercasename<TAB>CLASS<TAB>TYPE...
func normalizedString(r RR) string {
	// A string Go DNS makes has: domainname<TAB>TTL<TAB>...
	b := []byte(r.String())

	// find the first non-escaped tab, then another, so we capture where the TTL lives.
	esc := false
	ttlStart, ttlEnd := 0, 0
	for i := 0; i < len(b) && ttlEnd == 0; i++ {
		switch {
		case b[i] == '\\':
			esc = !esc
		case b[i] == '\t' && !esc:
			if ttlStart == 0 {
				ttlStart = i
				continue
			}
			if ttlEnd == 0 {
				ttlEnd = i
			}
		case b[i] >= 'A' && b[i] <= 'Z' && !esc:
			b[i] += 32
		default:
			esc = false
		}
	}

	// remove TTL.
	copy(b[ttlStart:], b[ttlEnd:])
	cut := ttlEnd - ttlStart
	return string(b[:len(b)-cut])
}
