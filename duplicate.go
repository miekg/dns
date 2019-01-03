package dns

import "reflect"

//go:generate go run duplicate_generate.go

// IsDuplicate checks of r1 and r2 are duplicates of each other, excluding the TTL.
// So this means the header data is equal *and* the RDATA is the same. Return true
// is so, otherwise false.
// It's is a protocol violation to have identical RRs in a message.
func IsDuplicate(r1, r2 RR) bool {
	if r1.Header().Class != r2.Header().Class {
		return false
	}
	if r1.Header().Rrtype != r2.Header().Rrtype {
		return false
	}
	if !isDulicateName(r1.Header().Name, r2.Header().Name) {
		return false
	}
	// ignore TTL

	// If either RR is lying about it's Rrtype, isDuplicateRdata will panic.
	// To prevent this, we check that they have the correct type here.
	expectedType := reflect.TypeOf(TypeToRR[r1.Header().Rrtype]())
	if reflect.TypeOf(r1) != expectedType || reflect.TypeOf(r2) != expectedType {
		return false
	}

	return isDuplicateRdata(r1, r2)
}

// isDulicateName checks if the domain names s1 and s2 are equal.
func isDulicateName(s1, s2 string) bool { return equal(s1, s2) }
