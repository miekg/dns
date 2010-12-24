package dns

import "time"

// All DNSSEC verification 

const (
	Year68 = 2 << (32 - 1)
)

// Translate the RRSIG's incep. and expir. time
// to the correct date, taking into account serial
// arithmetic
func timeToDate(t uint32) string {
	utc := time.UTC().Seconds()
	mod := (int64(t) - utc) / Year68

        // If needed assume wrap around(s)
        ti := time.SecondsToUTC(int64(t) + (mod * Year68)) // abs()? TODO
	return ti.Format("20060102030405")
}

// Is the signature (RRSIG) valid?
func validSignaturePeriod(start, end uint32) bool {
        utc := time.UTC().Seconds()       // maybe as parameter?? TODO MG
        return int64(start) <= utc && utc <= int64(end)
}
