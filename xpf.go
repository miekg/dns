package dns

import (
	"fmt"
	"net"
)

// XPF RR. See https://tools.ietf.org/html/draft-bellis-dnsop-xpf-04
type XPF struct {
	Hdr  RR_Header
	Data XPF_Data `dns:"xpf"` // This is seperated out to make this more compatible with the code generation
}

// XPF_Data encapsulates the xpf data for custom deserialization
type XPF_Data struct {
	IpVersion   uint8
	Protocol    uint8
	SrcAddress  net.IP
	DestAddress net.IP
	SrcPort     uint16
	DestPort    uint16
}

// Equals does a deep equals for the XPF Data
func (xpf_data *XPF_Data) Equals(xpf_data2 XPF_Data) bool {
	if xpf_data.IpVersion != xpf_data2.IpVersion {
		return false
	}
	if xpf_data.Protocol != xpf_data2.Protocol {
		return false
	}
	if !xpf_data.SrcAddress.Equal(xpf_data2.SrcAddress) {
		return false
	}
	if !xpf_data.DestAddress.Equal(xpf_data2.DestAddress) {
		return false
	}
	if xpf_data.SrcPort != xpf_data2.SrcPort {
		return false
	}
	if xpf_data.DestPort != xpf_data2.DestPort {
		return false
	}
	fmt.Println("meow")
	return true
}

func (rr *XPF) String() string {
	return fmt.Sprintf("%v Source=%v:%v Destination=%v:%v", rr.Hdr.String(), rr.Data.SrcAddress, rr.Data.SrcPort, rr.Data.DestAddress, rr.Data.DestPort)
}

func (rr *XPF) parse(c *zlexer, origin, file string) *ParseError {
	panic("dns: internal error: parse should never be called on XPF")
}

func (rr *XPF) len(off int, compression map[string]struct{}) int {
	l := rr.Hdr.len(off, compression)
	l++ // IpVersion
	l++ // Protocol
	switch rr.Data.IpVersion {
	case 4:
		l += net.IPv4len // SrcAddr
		l += net.IPv4len // DestAddr

	case 6:
		l += net.IPv6len // SrcAddr
		l += net.IPv6len // DestAddr
	}
	l += 2 // SrcPort
	l += 2 // DestPort
	//
	return l
}

func (r1 *XPF) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*XPF)
	if !ok {
		return false
	}
	return r1.Data.Equals(r2.Data)
}
