package dns

import (
	"encoding/hex"
	"errors"
	"net"
	"strconv"
)

// EDNS0 Option codes.
const (
	_           = iota
	EDNS0LLQ             // not used
	EDNS0UL              // not used
	EDNS0NSID            // NSID, RFC5001
	EDNS0SUBNET = 0x50fa // client-subnet draft
	_DO         = 1 << 7 // dnssec ok
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
			h, e := o.Pack()
			var r string
			if e == nil {
				for _, c := range h {
					r += "(" + string(c) + ")"
				}
				s += "  " + r
			}
		case *EDNS0_SUBNET:
			s += "\n; SUBNET: " + o.String()
		}
	}
	return s
}

func (rr *RR_OPT) Len() int {
	l := rr.Hdr.Len()
	for i := 0; i < len(rr.Option); i++ {
		lo, _ := rr.Option[i].Pack()
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
	// Pack returns the bytes of the option data.
	Pack() ([]byte, error)
	// Unpack sets the data as found in the packet. Is also sets
	// the length of the slice as the length of the option data.
	Unpack([]byte)
	// String returns the string representation of the option.
	String() string
}

type EDNS0_NSID struct {
	Code uint16 // Always EDNS0NSID
	Nsid string // This string needs to be hex encoded
}

func (e *EDNS0_NSID) Option() uint16 {
	return e.Code
}

func (e *EDNS0_NSID) Pack() ([]byte, error) {
	h, err := hex.DecodeString(e.Nsid)
	if err != nil {
		return nil, err
	}
	return h, nil
}

func (e *EDNS0_NSID) Unpack(b []byte) {
	e.Nsid = hex.EncodeToString(b)
}

func (e *EDNS0_NSID) String() string {
	return string(e.Nsid)
}

type EDNS0_SUBNET struct {
	Code          uint16 // Always EDNS0SUBNET
	Family        uint16 // 1 for IP, 2 for IP6
	SourceNetmask uint8
	SourceScope   uint8
	Address       net.IP
}

func (e *EDNS0_SUBNET) Option() uint16 {
	return e.Code
}

func (e *EDNS0_SUBNET) Pack() ([]byte, error) {
	b := make([]byte, 4)
	b[0], b[1] = packUint16(e.Family)
	b[2] = e.SourceNetmask
	b[3] = e.SourceScope
	switch e.Family {
	case 1:
		// just copy? TODO (also in msg.go...)
		ip := make([]byte, net.IPv4len)
		a := e.Address.To4()
		for i := 0; i < net.IPv4len; i++ {
			if i+1 > len(e.Address) {
				break
			}
			ip[i] = a[i]
		}
		b = append(b, ip...)
	case 2:
		ip := make([]byte, net.IPv6len)
		for i := 0; i < net.IPv6len; i++ {
			if i+1 > len(e.Address) {
				break
			}
			ip[i] = e.Address[i]
		}
		b = append(b, ip...)
	default:
		return nil, errors.New("bad address family")
	}
	return b, nil
}

func (e *EDNS0_SUBNET) Unpack(b []byte) {
	// TODO: length of b
	e.Family, _ = unpackUint16(b, 0)
	e.SourceNetmask = b[2]
	e.SourceScope = b[3]
	switch e.Family {
	case 1:
		if len(b) == 8 {
			e.Address = net.IPv4(b[4], b[5], b[6], b[7])
		}
	case 2:
		if len(b) == 20 {
			e.Address = net.IP{b[4], b[4+1], b[4+2], b[4+3], b[4+4],
				b[4+5], b[4+6], b[4+7], b[4+8], b[4+9], b[4+10],
				b[4+11], b[4+12], b[4+13], b[4+14], b[4+15]}
		}
	}
	return
}

func (e *EDNS0_SUBNET) String() (s string) {
	if e.Address.To4() != nil {
		s = e.Address.String()
	} else {
		s = "[" + e.Address.String() + "]"
	}
	s += "/" + strconv.Itoa(int(e.SourceNetmask)) + "/" + strconv.Itoa(int(e.SourceScope))
	return
}
