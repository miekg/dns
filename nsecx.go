package dns

import (
	"crypto/sha1"
	"fmt"
	"hash"
	"strings"
)

type saltWireFmt struct {
	Salt string `dns:"size-hex"`
}

// HashName hashes a string (label) according to RFC 5155. It returns the hashed string in uppercase.
func HashName(label string, ha uint8, iter uint16, salt string) string {
	saltwire := new(saltWireFmt)
	saltwire.Salt = salt
	wire := make([]byte, DefaultMsgSize)
	n, err := packSaltWire(saltwire, wire)
	if err != nil {
		return ""
	}
	wire = wire[:n]
	name := make([]byte, 255)
	off, err := PackDomainName(strings.ToLower(label), name, 0, nil, false)
	if err != nil {
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
	s.Write(name)
	s.Write(wire)
	nsec3 := s.Sum(nil)
	// k > 0
	for k := uint16(0); k < iter; k++ {
		s.Reset()
		s.Write(nsec3)
		s.Write(wire)
		nsec3 = s.Sum(nsec3[:0])
	}
	return toBase32(nsec3)
}

// Cover returns true if a name is covered by the NSEC3 record
func (rr *NSEC3) Cover(name string) bool {
	hname := HashName(name, rr.Hash, rr.Iterations, rr.Salt)
	owner := strings.ToUpper(rr.Hdr.Name)
	labels := Split(owner)
	if len(labels) < 2 {
		return false
	}
	if !strings.HasSuffix(strings.ToUpper(name), owner[labels[1]:]) {
		// name is outside zone
		fmt.Println("a")
		return false
	}

	hash := strings.TrimRight(owner[labels[0]:labels[1]], ".")
	fmt.Println("hname:", hname, "hash:", hash, "next:", rr.NextDomain)
	if hash == rr.NextDomain { // empty interval
		fmt.Println("b")
		return false
	}
	if hash > rr.NextDomain { // end of zone
		if hname > hash { // covered since there is nothing after hash
			fmt.Println("c")
			return true
		}
		fmt.Println("d")
		return hname < rr.NextDomain // if hname is before beginning of zone it is covered
	}
	if hname < hash { // hname is before hash, not covered
		fmt.Println("e")
		return false
	}
	fmt.Println("f")
	return hname < rr.NextDomain // if hname is before NextDomain is it covered (between hash and NextDomain
}

// Match returns true if a name matches the NSEC3 record
func (rr *NSEC3) Match(name string) bool {
	hname := HashName(name, rr.Hash, rr.Iterations, rr.Salt)
	owner := strings.ToUpper(rr.Hdr.Name)
	labels := Split(rr.Hdr.Name)
	if len(labels) < 2 {
		return false
	}
	if !strings.HasSuffix(strings.ToUpper(name), owner[labels[1]:]) {
		// name is outside zone
		return false
	}
	hash := strings.TrimRight(owner[labels[0]:labels[1]], ".")
	if hash == hname {
		return true
	}
	return false
}

func packSaltWire(sw *saltWireFmt, msg []byte) (int, error) {
	off, err := packStringHex(sw.Salt, msg, 0)
	if err != nil {
		return off, err
	}
	return off, nil
}
