package dns

import (
	"io"
	"hash"
	"strings"
	"crypto/sha1"
)

type saltWireFmt struct {
	Salt string "size-hex"
}

// Hash a string/label according to RFC5155
func Nsec3Hash(label string, ha int, iterations int, salt string) string {

	saltwire := new(saltWireFmt)
	saltwire.Salt = salt
	wire := make([]byte, DefaultMsgSize)
	n, ok := packStruct(saltwire, wire, 0)
	if !ok {
		return ""
	}
	wire = wire[:n]
	name := make([]byte, 255)
	off, ok1 := packDomainName(strings.ToLower(label), name, 0)
	if !ok1 {
		return ""
	}
	name = name[:off]

	var s hash.Hash
	switch ha {
	case HashSHA1:
		s = sha1.New()
        default:
                return ""
	}

	// k = 0
	name = append(name, wire...)
	io.WriteString(s, string(name))
	nsec3 := s.Sum()
        // k > 0
        for k := 0; k < iterations; k++ {
                s.Reset()
                nsec3 = append(nsec3, wire...)
                io.WriteString(s, string(nsec3))
                nsec3 = s.Sum()
        }
	return unpackBase32(nsec3)
}
