package dns

//go:generate go run duplicate_generate.go

// IsDuplicate checks of r1 and r2 are duplicates of each other, excluding the TTL.
// So this means the header data is equal *and* the RDATA is the same. Return true
// is so, otherwise false.
// It's is a protocol violation to have identical RRs in a message.
func IsDuplicate(r1, r2 RR) bool {
	// Check whether the record header is identical.
	h1, h2 := r1.Header(), r2.Header()
	if h1.Class != h2.Class {
		return false
	}
	if h1.Rrtype != h2.Rrtype {
		return false
	}
	if !isDulicateName(h1.Name, h2.Name) {
		return false
	}
	// ignore TTL

	// Check whether the RDATA is identical.
	return r1.isDuplicate(r2)
}

// isDulicateName checks if the domain names s1 and s2 are equal.
func isDulicateName(s1, s2 string) bool { return equal(s1, s2) }
