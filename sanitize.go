package dns

// Dedup removes identical RRs from rrs. It preserves the original ordering.
func Dedup(rrs []RR) []RR {
	m := make(map[string]RR)

	for _, r := range rrs {
		key := mapKey(r)
		if _, ok := m[key]; ok {
			continue
		}
		m[key] = r
	}
	if len(m) == len(rrs) {
		return rrs
	}
	var i = 0
	var r RR
	for i, r = range rrs {
		if len(m) == 0 {
			break
		}
		key := mapKey(r)
		delete(m, key)
	}
	return rrs[:i]
}

// Returns the rr as a string with the TTL.
func mapKey(r RR) string { return Sprintf("%n%t%c%r", r) }
