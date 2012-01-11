package dns

import (
	"crypto/sha1"
	"hash"
	"io"
	"strings"
)

type saltWireFmt struct {
	Salt string "size-hex"
}

// HashName hashes a string or label according to RFC5155. It returns
// the hashed string.
func HashName(label string, ha, iter int, salt string) string {
	saltwire := new(saltWireFmt)
	saltwire.Salt = salt
	wire := make([]byte, DefaultMsgSize)
	n, ok := packStruct(saltwire, wire, 0, nil, false)
	if !ok {
		return ""
	}
	wire = wire[:n]
	name := make([]byte, 255)
	off, ok1 := PackDomainName(strings.ToLower(label), name, 0, nil, false)
	if !ok1 {
		return ""
	}
	name = name[:off]
	var s hash.Hash
	switch ha {
	case SHA1:
		s = sha1.New()
	default:
		return ""
	}

	// k = 0
	name = append(name, wire...)
	io.WriteString(s, string(name))
	nsec3 := s.Sum(nil)
	// k > 0
	for k := 0; k < iter; k++ {
		s.Reset()
		nsec3 = append(nsec3, wire...)
		io.WriteString(s, string(nsec3))
		nsec3 = s.Sum(nil)
	}
	return unpackBase32(nsec3)
}

// Hash the ownername and the next owner name in an NSEC3 record according
// to RFC 5155.
// Use the parameters from the NSEC3 itself.
func (nsec3 *RR_NSEC3) HashNames() {
	nsec3.Header().Name = HashName(nsec3.Header().Name, int(nsec3.Hash), int(nsec3.Iterations), nsec3.Salt)
	nsec3.NextDomain = HashName(nsec3.NextDomain, int(nsec3.Hash), int(nsec3.Iterations), nsec3.Salt)
}

// NsecVerify verifies the negative response (NXDOMAIN/NODATA) in 
// the message m. 
// NsecVerify returns nil when the NSECs in the message contain
// the correct proof. This function does not validates the NSECs
func (m *Msg) NsecVerify(q Question) error {

	return nil
}

// Nsec3Verify verifies ...
func (m *Msg) Nsec3Verify(q Question) error {

	return nil
}
