package dns

import (
	"crypto/sha1"
	"time"
)

const (
	// RFC1982 serial arithmetic
	year68 = 2 << (32 - 1)
)

// Convert an DNSKEY record to a DS record.
func (k *RR_DNSKEY) ToDS(hash int) *RR_DS {
	switch hash {
	case HashSHA1:
		var _ = sha1.New()

	case HashSHA256:

	}
	return nil
}

// Calculate the keytag of the DNSKEY
func (k *RR_DNSKEY) Tag() (keytag int) {
	switch k.Algorithm {
	case AlgRSAMD5:
                println("Keytag RSAMD5. Todo")
		keytag = 0
	default:
		// Might encode header length too, so that
		// we dont need to pack/unpack all the time
		buf := make([]byte, 4096)
		off1, ok := packRR(k, buf, 0)
		if !ok {
			return 0
		}

		start := off1 - int(k.Header().Rdlength)
		end := start + int(k.Header().Rdlength)
		for i, v := range buf[start:end] {
			if i&1 != 0 {
				keytag += int(v)
			} else {
				keytag += int(v) << 8
			}
		}
		keytag += (keytag >> 16) & 0xFFFF
		keytag &= 0xFFFF
	}
	return
}

// Validate an rrset with the signature and key. Note the
// signature validate period is NOT checked. Used 
// ValidSignaturePeriod for that
func (s *RR_RRSIG) Valid(rrset []RR, key *RR_DNSKEY) bool {
	return false
}

// Translate the RRSIG's incep. and expir. time to the correct date.
// Taking into account serial arithmetic (RFC 1982)
func timeToDate(t uint32) string {
	utc := time.UTC().Seconds()
	mod := (int64(t) - utc) / year68

	// If needed assume wrap around(s)
	ti := time.SecondsToUTC(int64(t) + (mod * year68)) // abs()? TODO
	return ti.Format("20060102030405")
}

// Work on a signature RR_RRSIG
// Using RFC1982 calculate if a signature is valid
func ValidSignaturePeriod(start, end uint32) bool {
	utc := time.UTC().Seconds() // maybe as parameter?? TODO MG
	return int64(start) <= utc && utc <= int64(end)
}
