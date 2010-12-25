package dns

import "time"

// All DNSSEC verification 

const (
	year68 = 2 << (32 - 1)
)

// Translate the RRSIG's incep. and expir. time to the correct date.
// Taking into account serial arithmetic (RFC 1982)
func timeToDate(t uint32) string {
	utc := time.UTC().Seconds()
	mod := (int64(t) - utc) / year68

	// If needed assume wrap around(s)
	ti := time.SecondsToUTC(int64(t) + (mod * year68)) // abs()? TODO
	return ti.Format("20060102030405")
}

// Using RFC1982 calculate if a signature is valid
func validSignaturePeriod(start, end uint32) bool {
	utc := time.UTC().Seconds() // maybe as parameter?? TODO MG
	return int64(start) <= utc && utc <= int64(end)
}
