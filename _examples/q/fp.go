// Package main provides ...
package main

import (
	"dns"
	"strconv"
	"strings"
)

// fingerPrint creates a (short) string representation of a dns message.
// If a bit is set we uppercase the name 'AD' otherwise it's lowercase 'ad'.
func msgToFingerPrint(m *dns.Msg) string {
	if m == nil {
		return "<nil>"
	}
	h := m.MsgHdr

	// Use the same order as in Perl's fpdns.
	// But use more flags.
	s := dns.Opcode_str[h.Opcode]
	s += "," + dns.Rcode_str[h.Rcode]
	s += valueOf(h.Response, ",qr")
	s += valueOf(h.Authoritative, ",aa")
	s += valueOf(h.Truncated, ",tc")
	s += valueOf(h.RecursionDesired, ",rd")
	s += valueOf(h.AuthenticatedData, ",ad")
	s += valueOf(h.CheckingDisabled, ",ad")
	s += valueOf(h.Zero, ",z")

	s += "," + strconv.Itoa(len(m.Question))
	s += "," + strconv.Itoa(len(m.Answer))
	s += "," + strconv.Itoa(len(m.Ns))
	s += "," + strconv.Itoa(len(m.Extra))

	// EDNS0
	// V0,DO,4096 (all on)
	// v0,do,0    (all off)
	for _, r := range m.Extra {
		if r.Header().Rrtype == dns.TypeOPT {
                        // version is always 0 - and I cannot set it anyway
			s += valueOf(r.(*dns.RR_OPT).Do(), ",do")
			s += "," + strconv.Itoa(int(r.(*dns.RR_OPT).UDPSize()))
			return s
		}
	}
	s += ",do,0"
	return s
}

// Create a dns message from a fingerprint string
func fingerPrintToProbe(fp string, q dns.Question) *dns.Msg {

	return nil
}

func valueOf(x bool, w string) string {
	if x {
		return strings.ToUpper(w)
	}
	return strings.ToLower(w)
}
