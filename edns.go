package dns

import (
	"encoding/hex"
	"strconv"
)

// EDNS0 Option codes.
const (
	_              = iota
	OptionCodeLLQ           // not used
	OptionCodeUL            // not used
	OptionCodeNSID          // NSID, RFC5001
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

// Adding an EDNS0 record to a message is done as follows:
//      opt := new(RR_OPT)
//      opt.Hdr = dns.RR_Header{Name: "", Rrtype: TypeOPT}
//      opt.SetVersion(0)       // set version to zero
//      opt.SetDo()             // set the DO bit
//      opt.SetUDPSize(4096)    // set the message size
//      m.Extra = make([]RR, 1)
//      m.Extra[0] = opt        // add OPT RR to the message
type RR_OPT struct {
	Hdr    RR_Header
	Option []Option "OPT" // tag is used in Pack and Unpack
}

func (rr *RR_OPT) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_OPT) String() string {
	s := "\n;; OPT PSEUDOSECTION:\n; EDNS: version " + strconv.Itoa(int(rr.Version())) + "; "
	if rr.Do() {
		s += "flags: do; "
	} else {
		s += "flags: ; "
	}
	s += "udp: " + strconv.Itoa(int(rr.UDPSize()))

	for _, o := range rr.Option {
		switch o.Code {
		case OptionCodeNSID:
			s += "\n; NSID: " + o.Data
			h, e := hex.DecodeString(o.Data)
			var r string
			if e == nil {
				for _, c := range h {
					r += "(" + string(c) + ")"
				}
				s += "  " + r
			}
		}
	}
	return s
}

func (rr *RR_OPT) Len() int {
	l := rr.Hdr.Len()
	for i := 0; i < len(rr.Option); i++ {
		l += 2 + len(rr.Option[i].Data)/2
	}
	return l
}

// Version returns the EDNS version.
func (rr *RR_OPT) Version() uint8 {
	return uint8(rr.Hdr.Ttl & 0x00FF00FFFF)
}

// SetVersion sets the version of EDNS. This is usually zero.
func (rr *RR_OPT) SetVersion(v uint8) {
	rr.Hdr.Ttl = rr.Hdr.Ttl&0xFF00FFFF | uint32(v)
}

// UDPSize gets the UDP buffer size.
func (rr *RR_OPT) UDPSize() uint16 {
	return rr.Hdr.Class
}

// SetUDPSize sets the UDP buffer size.
func (rr *RR_OPT) SetUDPSize(size uint16) {
	rr.Hdr.Class = size
}

/* from RFC 3225
          +0 (MSB)                +1 (LSB)
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0: |   EXTENDED-RCODE      |       VERSION         |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
2: |DO|                    Z                       |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

// Do gets the value of the DO (DNSSEC OK) bit.
func (rr *RR_OPT) Do() bool {
	return byte(rr.Hdr.Ttl>>8)&_DO == _DO
}

// SetDo sets the DO (DNSSEC OK) bit.
func (rr *RR_OPT) SetDo() {
	b1 := byte(rr.Hdr.Ttl >> 24)
	b2 := byte(rr.Hdr.Ttl >> 16)
	b3 := byte(rr.Hdr.Ttl >> 8)
	b4 := byte(rr.Hdr.Ttl)
	b3 |= _DO // Set it
	rr.Hdr.Ttl = uint32(b1)<<24 | uint32(b2)<<16 | uint32(b3)<<8 | uint32(b4)
}

// Nsid returns the NSID as hex character string.
func (rr *RR_OPT) Nsid() string {
	return "NSID: " + rr.Option[0].Data
}

// SetNsid sets the NSID from a hex character string.
// Use the empty string when requesting an NSID.
func (rr *RR_OPT) SetNsid(hexnsid string) {
	rr.Option = append(rr.Option, Option{OptionCodeNSID, hexnsid})
}
