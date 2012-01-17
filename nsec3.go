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
        var nsec3 []*RR_NSEC3
	if len(m.Answer) > 0 && len(m.Ns) > 0 {
		// Wildcard expansion
		// Closest encloser inferred from SIG in authority and qname
		println("EXPANDED WILDCARD PROOF or DNAME CNAME")
		println("NODATA")
		// I need to check the type bitmap
		// wildcard bit not set?
		// MM: No need to check the wildcard bit here:
		//     This response has only 1 NSEC4 and it does not match
		//     the closest encloser (it covers next closer).
	}

	if len(m.Answer) == 0 && len(m.Ns) > 0 {
		// Maybe an NXDOMAIN, we only know when we check
                for _, n := range m.Ns {
                        if n.Rrtype == TypeNSEC3 {
                                nsec3 = append(nsec3, n.(*RR_NSEC3))
                        }
                }
                if len(nsec3) == 0 {
                        return ErrNoNsec3

		hash := nsec3[0].(*RR_NSEC3).Hash
		iter := nsec3[0].(*RR_NSEC3).Iterations
		salt := nsec3[0].(*RR_NSEC3).Salt
		ce := "goed.fout."
	ClosestEncloser:
		for _, nsec := range nsec3 {
			for _, candidate := range LabelSlice(q.Name) {
				println("H:", HashName(ce1, algo, iter, salt)+suffix)
				println("N:", strings.ToUpper(nsec.Header().Name))
				if HashName(ce1, algo, iter, salt)+suffix == strings.ToUpper(nsec.Header().Name) {
					ce = ce1
					break ClosestEncloser
				}
			}
		}
		if ce == "goed.fout." {
			// If we didn't find the closest here, we have a NODATA wilcard response
			println("CE NIET GEVONDEN")
			println(" (WILDCARD) NODATA RESPONSE")
			// chop the qname, append the wildcard label, and see it we have a match
			// Zijn we nog wel in de zone bezig als we deze antwoord hebben
			// dat moeten we toch wel controleren TODO(MG)
			// MM: source-of-synthesis (source) = *.closest-encloser (ce)
			// 1. ce is an ancestor of QNAME of which source is matched by an
			// NSEC4 RR present in the response.
			// 2. The name one label longer than ce (but still an ancestor of --
			// or equal to -- QNAME) is covered by an NSEC4 RR present in the
			// response.
			// 3. Are the NSEC4 RRs from the proper zone?
			// The NSEC4 that matches the wildcard RR is: 
			// Check that the signer field in the RRSIG on both NSEC4 RRs
			// is the same. If so, both NSEC4 RRs are from the same zone.

		Synthesis:
			for _, nsec := range nsec4 {
				for _, ce1 := range LabelSlice(q.Name) {
					source := "*." + ce1
					if ce1 == "." {
						source = "*."

					}
					println(source, ":", HashName(source, algo, iter, salt))
					println("               : ", strings.ToUpper(nsec.Header().Name))
					if HashName(source, algo, iter, salt)+suffix == strings.ToUpper(nsec.Header().Name) {
						ce = ce1
						break Synthesis
					}
				}
			}
			println("Source of synthesis found, CE = ", ce)
			// Als niet gevonden, shit hits the fan?!
			// MM: je hebt nog niet de gewone NODATA geprobeerd...
			// need nsec that matches the qname directly
			//                        if HashName(q.Name, algo, iter, salt)+suffix == strings.ToUpper(nsec.Header().Name) 


			if ce == "goed.fout." {
				println("Source of synth not found")
			}
		}

		// if q.Name == ce -> Check nodata, wildcard flag off	
		if strings.ToUpper(q.Name) == strings.ToUpper(ce) {
			println("WE HAVE TO DO A NODATA PROOF 2")
			for _, nsec := range nsec4 {
				println(HashName(ce, algo, iter, salt)+suffix, strings.ToUpper(nsec.Header().Name))
				if HashName(ce, algo, iter, salt)+suffix == strings.ToUpper(nsec.Header().Name) {
					fmt.Printf("We should not have the type %s (%d)? %v\n", Rr_str[q.Qtype], q.Qtype, !bitmap(nsec.(*RR_NSEC4), q.Qtype))
					fmt.Printf("                    we have: %v\n", nsec.(*RR_NSEC4).TypeBitMap)
					if !bitmap(nsec.(*RR_NSEC4), q.Qtype) {
						println("NODATA IS PROVEN, IF NSEC4S ARE VALID")
					}
					return nil

				}
			}
			println("CHECK TYPE BITMAP 2")
			return nil
		}

		nc := NextCloser(q.Name, ce)

		println("Clostest encloser found:", ce, HashName(ce, algo, iter, salt))
		println("Next closer:", nc)
		// One of these NSEC4s MUST cover the next closer


		println("NEXT CLOSER PROOF")
	NextCloser:
		for _, nsec := range nsec4 {
			// NSEC-like, whole name
			println(nc)
			println(strings.ToUpper(HashName(nc, algo, iter, salt)))
			println(nsec.Header().Name)
			println(nsec.(*RR_NSEC4).NextDomain)

			if CoversName(HashName(nc, algo, iter, salt), nsec.Header().Name, nsec.(*RR_NSEC4).NextDomain) {
				// Wildcard bit must be off
				println("* covers *")
				if nsec.(*RR_NSEC4).Flags&WILDCARD == 1 {
					println("Wildcard set! Error")
					println("NOT PROVEN NXDOMAIN")
				} else {
					println("Wildcard not set")
					println("NXDOMAIN IS PROVEN, IF NSEC4S ARE VALID")
					break NextCloser
				}
			}
		}
		// If the nextcloser MATCHES the owername of one of the NSEC4s we have a NODATA response

	}
	return nil
}
