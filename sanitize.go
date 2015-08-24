package dns

import "bytes"

// Contains functions the sanitize RRsets and messages.

// Dedup will deduplicate rrs. It will detect and remove RRs that have
// an idential ownername, type, class and rdata. Note that the order
// of the RRs in the set is randomized after this function. TODO(miek): fix the latter.
// panic when not valid???
func Dedup(rrs []RR) []RR {
	buf := make([]byte, MaxMsgSize)
	m := make(map[string]RR)

	for _, r := range rrs {
		n, err := PackStruct(r, buf, 0)
		if err != nil {
			panic("dns: failure to dedup: " + err.Error())
		}

		// We are going to normalized the domainname (lowercase it)
		end, _ := rawDomainNameIndex(buf, 0) // TODO(miek): check boolean?
		rawSetBytes(buf, 0, end, bytes.ToLower)

		// And set the TTL to 0.
		rawSetBytes(buf, end+5, end+10, func([]byte) []byte {
			return []byte{0, 0, 0, 0}
		})

		key := string(buf[:n]) // make a string (and thus copy) for use in the map

		if r1, ok := m[key]; ok {
			if r1.Header().Ttl > r.Header().Ttl {
				m[key].Header().Ttl = r.Header().Ttl
			}
			continue
		}
		m[key] = r
	}

	// A map is random so the order here is wrong
	// We can range over the original rrs, but to find the key in the
	// map we need to normalize again... TODO(miek)
	i := 0
	for _, r := range m {
		rrs[i] = r
		i++
	}
	return rrs[:i]
}
