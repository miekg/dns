package dns

import (
	"crypto/sha1"
	"crypto/sha256"
        "encoding/hex"
	"time"
        "io"
)

const (
	// RFC1982 serial arithmetic
	year68 = 2 << (32 - 1)
)

// Convert an DNSKEY record to a DS record.
func (k *RR_DNSKEY) ToDS(hash int) *RR_DS {
        ds := new(RR_DS)
        ds.Hdr.Name = k.Hdr.Name
        ds.Hdr.Class = k.Hdr.Class
        ds.Hdr.Ttl  = k.Hdr.Ttl
        ds.Hdr.Rrtype = TypeDS
        ds.KeyTag = k.KeyTag()
        ds.Algorithm = k.Algorithm
        ds.DigestType = uint8(hash)

        // Generic function that gives back a buffer with the rdata?? TODO(MG)
        // Find the rdata portion for the key (again)
        // (keytag does this too)
        buf := make([]byte, 4096)
        off1, ok := packRR(k, buf, 0)
        if !ok {
                return nil
        }

        start := off1 - int(k.Header().Rdlength)
        end := start + int(k.Header().Rdlength)
        // buf[start:end] is the rdata of the key
        buf = buf[start:end]
        // Now the owner name
        owner := make([]byte, 255)
        off1, ok = packDomainName(k.Hdr.Name, owner, 0)
        if !ok {
                return nil
        }
        owner = owner[:off1]
        // digest buffer
        digest := append(owner, buf...)

        /* 
         * from RFC4034
         * digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
         * "|" denotes concatenation
         * DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.
        */

	switch hash {
	case HashSHA1:
		s := sha1.New()
                io.WriteString(s, string(digest))
                ds.Digest = hex.EncodeToString(s.Sum())
	case HashSHA256:
                s := sha256.New()
                io.WriteString(s, string(digest))
                ds.Digest = hex.EncodeToString(s.Sum())
        case HashGOST94:

        default:
                // wrong hash value
                return nil
	}
	return ds
}

// Calculate the keytag of the DNSKEY.
func (k *RR_DNSKEY) KeyTag() uint16 {
        var keytag int
	switch k.Algorithm {
	case AlgRSAMD5:
                println("Keytag RSAMD5. Todo")
		keytag = 0
	default:
		// Might encode header length too, so that
		// we dont need to pack/unpack all the time
                // Or a shadow structure, with the wiredata and header
		buf := make([]byte, 4096)
		off1, ok := packRR(k, buf, 0)
		if !ok {
			return 0
		}

		start := off1 - int(k.Header().Rdlength)
		end := start + int(k.Header().Rdlength)
		for i, v := range buf[start:end] {
			if i&1 != 0 {
				keytag += int(v)         // must be larger than uint32
			} else {
				keytag += int(v) << 8
			}
		}
		keytag += (keytag >> 16) & 0xFFFF
		keytag &= 0xFFFF
	}
	return uint16(keytag)
}

// Validate an rrset with the signature and key. This is the
// cryptographic test, the validity period most be check separately.
func (s *RR_RRSIG) Secure(rrset []RR, key *RR_DNSKEY) bool {
	return false
}

// Using RFC1982 calculate if a signature period is valid
func (s *RR_RRSIG) PeriodOK() bool {
	utc := time.UTC().Seconds()
	modi := (int64(s.Inception) - utc) / year68
	mode := (int64(s.Expiration) - utc) / year68
        ti := int64(s.Inception) + (modi * year68)
        te := int64(s.Expiration) + (mode * year68)
	return ti <= utc && utc <= te
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

