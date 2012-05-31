package dns

import (
	"encoding/hex"
	"net"
	"strconv"
)

// EDNS0 Option codes.
const (
	_                = iota
	OptionLLQ             // not used
	OptionUL              // not used
	OptionNSID            // NSID, RFC5001
	OptionSUBNET = 0x50fa // client-subnet draft
	_DO              = 1 << 7 // dnssec ok
)

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
	Option []EDNS0 `dns:"opt"` // tag is used in Pack and Unpack
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
		switch o.(type) {
		case *EDNS0_NSID:
			s += "\n; NSID: " + o.String()
			h, e := o.Bytes()
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
		lo, _ := rr.Option[i].Bytes()
		l += 2 + len(lo)
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

// EDNS0 defines a EDNS0 Option
type EDNS0 interface {
	// Option return the option code for the option.
	Option() uint16
	// Bytes returns the bytes of the option data.
	Bytes() ([]byte, error)
	// String returns the string representation of the option.
	String() string
	// SetBytes sets the data as found in the packet. Is also sets
	// the length of the slice as the length of the option data.
	SetBytes([]byte)
}

type EDNS0_NSID struct {
	Code uint16
	Nsid string // This string must be encoded as Hex
}

func (e *EDNS0_NSID) Option() uint16 {
	return e.Code
}

func (e *EDNS0_NSID) Bytes() ([]byte, error) {
	h, err := hex.DecodeString(e.Nsid)
	if err != nil {
		return nil, err
	}
	return h, nil
}

func (e *EDNS0_NSID) String() string {
	return string(e.Nsid)
}

func (e *EDNS0_NSID) SetBytes(b []byte) {
	e.Code = OptionNSID
	e.Nsid = hex.EncodeToString(b)
}

type EDNS0_SUBNET struct {
	Code          uint16
	Family        uint16
	SourceNetmask uint8
	SourceScope   uint8
	Address       []net.IP
}
