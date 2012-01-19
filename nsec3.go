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

// HashName hashes a string (label) according to RFC5155. It returns the hashed string.
func HashName(label string, ha, iter int, salt string) string {
	saltwire := new(saltWireFmt)
	saltwire.Salt = salt
	wire := make([]byte, DefaultMsgSize)
	n, ok := packStruct(saltwire, wire, 0)
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

// HashNames hashes the ownername and the next owner name in an NSEC3 record according to RFC 5155.
// It uses the paramaters as set in the NSEC3 record. The string zone is appended to the hashed
// ownername.
func (nsec3 *RR_NSEC3) HashNames(zone string) {
	nsec3.Header().Name = strings.ToLower(HashName(nsec3.Header().Name, int(nsec3.Hash), int(nsec3.Iterations), nsec3.Salt)) + "." + zone
	nsec3.NextDomain = HashName(nsec3.NextDomain, int(nsec3.Hash), int(nsec3.Iterations), nsec3.Salt)
}

// NsecVerify verifies an denial of existence response with NSECs
// NsecVerify returns nil when the NSECs in the message contain
// the correct proof. This function does not validates the NSECs.
func (m *Msg) NsecVerify(q Question) error {

	return nil
}

// Nsec3Verify verifies an denial of existence response with NSEC3s.
// This function does not validate the NSEC3s.
func (m *Msg) Nsec3Verify(q Question) error {
	var (
		nsec3    []*RR_NSEC3
		ncdenied = false // next closer denied
		sodenied = false // source of synthesis denied
	)
	if len(m.Answer) > 0 && len(m.Ns) > 0 {
		// Wildcard expansion
		// Closest encloser inferred from SIG in authority and qname
		// println("EXPANDED WILDCARD PROOF or DNAME CNAME")
		// println("NODATA")
		// I need to check the type bitmap
		// wildcard bit not set?
		// MM: No need to check the wildcard bit here:
		//     This response has only 1 NSEC4 and it does not match
		//     the closest encloser (it covers next closer).
	}
	if len(m.Answer) == 0 && len(m.Ns) > 0 {
		// Maybe an NXDOMAIN, we only know when we check
		for _, n := range m.Ns {
			if n.Header().Rrtype == TypeNSEC3 {
				nsec3 = append(nsec3, n.(*RR_NSEC3))
			}
		}
		if len(nsec3) == 0 {
			return ErrDenialNsec3
		}

		hash := int(nsec3[0].Hash)
		iter := int(nsec3[0].Iterations)
		salt := nsec3[0].Salt
		ce := "" // closest encloser
		nc := "" // next closer
		so := "" // source of synthesis
		lastchopped := ""
		labels := SplitLabels(q.Name)

		// Find the closest encloser and create the next closer
		for _, nsec := range nsec3 {
			candidate := ""
			firstlab := strings.ToUpper(SplitLabels(nsec.Header().Name)[0])
			for i := len(labels) - 1; i >= 0; i-- {
				candidate = labels[i] + "." + candidate
				if HashName(candidate, hash, iter, salt) == firstlab {
					ce = candidate
				}
				lastchopped = labels[i]
			}
		}
		if ce == "" { // what about root label?
			return ErrDenialCe
		}
		nc = lastchopped + "." + ce
		so = "*." + ce

		// Check if the next closer is covered and thus denied
		for _, nsec := range nsec3 {
			firstlab := strings.ToUpper(SplitLabels(nsec.Header().Name)[0])
			nextdom := strings.ToUpper(nsec.NextDomain)
			hashednc := HashName(nc, hash, iter, salt)
			if hashednc > firstlab && hashednc < nextdom {
				ncdenied = true
                                break
			}
		}
		if !ncdenied {
			return ErrDenialNc
		}

                // Check if the source of synthesis is covered and thus denied
		for _, nsec := range nsec3 {
			firstlab := strings.ToUpper(SplitLabels(nsec.Header().Name)[0])
			nextdom := strings.ToUpper(nsec.NextDomain)
			hashedso := HashName(so, hash, iter, salt)
			if hashedso > firstlab && hashedso < nextdom {
				sodenied = true
                                break
			}
		}
		if !sodenied {
			return ErrDenialSo
		}
                println("NSEC3 proof succesfully proofed")
                return nil
	}

	/*
	*/
	return nil
}
