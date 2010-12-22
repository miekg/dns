package dns

// This is the base layer for ENDS, in practise
// You'll only need to set updsize, do bit, and??

const (
        OptionCodeLLQ   = 1
        OptionCodeUL    = 2
        OptionCodeNSID  = 3
        // EDNS flag bits (put in Z section)
        _DO = 1 << 15  // dnssec ok
)

// Need PackOption I guess?? TODO
type Option struct {
        Code    uint16
//        Length  uint16
        Data    string "hex" // len(data) is must be encode in packet
}

// EDNS extended RR.
type EDNS0_Header struct {
        Name          string "extended-name"
        Opt           uint16 // was type
        UDPSize       uint16 // was class
        ExtendedRcode uint8  // was TTL
        Version       uint8  // was TTL
        Z             uint16 // was TTL (all flags should be put here
        Rdlength      uint16 // length of data after the header
}

type RR_EDNS0 struct {
        Hdr     RR_Header       // this must become a EDNS0_Header
        Option  []Option
}

func (rr *RR_EDNS0) Header() *RR_Header {
        return &rr.Hdr
}

func (rr *RR_EDNS0) String() string {
        var s string
        for _, o := range rr.Option {
                switch o.Code {
                case OptionCodeNSID:
                        s += "NSID: " + o.Data
                }
        }
        return s
}
