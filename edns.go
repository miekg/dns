package dns

import (
	"strconv"
)

// EDNS0 Options and Do bit
const (
	OptionCodeLLQ  = 1      // Not used
	OptionCodeUL   = 2      // Not used
	OptionCodeNSID = 3      // NSID, RFC5001
	_DO            = 1 << 7 // dnssec ok
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


/* from RFC 3225
             +0 (MSB)                +1 (LSB)
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   0: |   EXTENDED-RCODE      |       VERSION         |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   2: |DO|                    Z                       |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

// Set/Get the DoBit 
func (rr *RR_OPT) DoBit(do, set bool) bool {
	if set {
		b1 := byte(rr.Hdr.Ttl >> 24)
		b2 := byte(rr.Hdr.Ttl >> 16)
		b3 := byte(rr.Hdr.Ttl >> 8)
		b4 := byte(rr.Hdr.Ttl)
		b3 |= _DO // Set it
		rr.Hdr.Ttl = uint32(b1)<<24 | uint32(b2)<<16 | uint32(b3)<<8 | uint32(b4)
		return true
	} else {
		return byte(rr.Hdr.Ttl >> 8) &_DO == _DO
	}
	return true // dead code, bug in Go
}

// when set is true, set the nsid, otherwise get it
func (rr *RR_OPT) Nsid(nsid string, set bool) string {
	// RR.Option[0] to be set
	return ""
}
