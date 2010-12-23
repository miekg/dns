package dns

// Implementation of EDNS0, RFC 2671
const (
	OptionCodeLLQ  = 1
	OptionCodeUL   = 2
	OptionCodeNSID = 3
	// EDNS flag bits (put in Z section)
	_DO = 1 << 15 // dnssec ok
)

type Option struct {
	Code uint16
	Data string "hex"
}

// EDNS extended RR.
// Not used yet
type EDNS0_Header struct {
	Name          string "extended-name"
	Opt           uint16 // was type, but is always TypeOPT
	UDPSize       uint16 // was class
	ExtendedRcode uint8  // was TTL
	Version       uint8  // was TTL
	Z             uint16 // was TTL (all flags should be put here)
	Rdlength      uint16 // length of data after the header
}

type RR_OPT struct {
	Hdr    RR_Header // this must become a EDNS0_Header
	Option []Option  "OPT" // Tag is used in pack and unpack
}

func (rr *RR_OPT) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_OPT) String() string {
	s := rr.Hdr.String()
	for _, o := range rr.Option {
		switch o.Code {
		case OptionCodeNSID:
			s += "NSID: " + o.Data
		}
	}
	return s
}
