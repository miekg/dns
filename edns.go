package dns

import (
	"strconv"
)

// EDNS0 Options and Do bit
const (
	OptionCodeLLQ  = 1 // Not used
	OptionCodeUL   = 2 // Not used
	OptionCodeNSID = 3 // NSID, RFC5001
	_DO = 1 << 7 // dnssec ok
)

// An ENDS0 option rdata element.
type Option struct {
	Code uint16
	Data string "hex"
}

/* 
 * EDNS extended RR.
 * This is the EDNS0 Header
 * 	Name          string "domain-name"
 * 	Opt           uint16 // was type, but is always TypeOPT
 * 	UDPSize       uint16 // was class
 * 	ExtendedRcode uint8  // was TTL
 * 	Version       uint8  // was TTL
 * 	Z             uint16 // was TTL (all flags should be put here)
 * 	Rdlength      uint16 // length of data after the header
 */

type RR_OPT struct {
	Hdr    RR_Header
	Option []Option "OPT" // Tag is used in pack and unpack
}

func (rr *RR_OPT) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_OPT) String() string {
	s := ";; EDNS: version " + strconv.Itoa(int(rr.Version(0, false))) + "; "
	if rr.DoBit(false, false) {
		s += "flags: do; "
	} else {
		s += "flags: ; "
	}
	s += "udp: " + strconv.Itoa(int(rr.UDPSize(0, false))) + ";"

	for _, o := range rr.Option {
		switch o.Code {
		case OptionCodeNSID:
			s += " nsid: " + o.Data + ";"
		}
	}
	return s
}

// Set the version of edns
func (rr *RR_OPT) Version(v uint8, set bool) uint8 {
	return 0
}

// Set/Get the UDP buffer size
func (rr *RR_OPT) UDPSize(size uint16, set bool) uint16 {
	if set {
		rr.Hdr.Class = size
	}
	return rr.Hdr.Class
}

// Set/Get the DoBit 
func (rr *RR_OPT) DoBit(do, set bool) bool {
	// rr.TTL last 2 bytes, left most bit
	// See line 239 in msg.go for TTL encoding
	if set {
		leftbyte := byte(rr.Hdr.Ttl >> 24)
		leftbyte = leftbyte | _DO
		rr.Hdr.Ttl = uint32(leftbyte << 24)
		return true
	} else {
		// jaja?? TODO(MG)
		leftbyte := byte(rr.Hdr.Ttl >> 24)
		return leftbyte&_DO == 1
	}
	return true // dead code, bug in Go
}

// when set is true, set the nsid, otherwise get it
func (rr *RR_OPT) Nsid(nsid string, set bool) string {
	// RR.Option[0] to be set
	return ""
}
