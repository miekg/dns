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
	owner := make([]byte, 255)
	off, ok1 := packDomainName(strings.ToLower(label), owner, 0)
	if !ok1 {
		return ""
	}
	owner = owner[:off]

	var s hash.Hash
	switch ha {
	case HashSHA1:
		s = sha1.New()
	}

	// k = 0
	h := append(owner, wire...)
	io.WriteString(s, string(h))
	nsec3 := s.Sum()

	for k := 1; k < iterations; k++ {
                h = append(nsec3, wire...)
                io.WriteString(s, string(h))
                nsec3 = s.Sum()
	}
	return unpackBase32(nsec3)
}
