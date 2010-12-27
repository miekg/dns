// EDNS0 OTP RR implementation. Define the OPT RR and some
// convience functions to operate on it.
package dns

// EDNS0 option codes
const (
	OptionCodeLLQ  = 1      // Not used
	OptionCodeUL   = 2      // Not used
	OptionCodeNSID = 3      // NSID, RFC5001
	// EDNS flag bits (put in Z section)
	_DO = 1 << 15 // dnssec ok
)

// An ENDS0 option rdata element.
type Option struct {
	Code uint16
	Data string "hex"
}

/* EDNS extended RR.
This is the EDNS0 Header
	Name          string "domain-name"
	Opt           uint16 // was type, but is always TypeOPT
	UDPSize       uint16 // was class
	ExtendedRcode uint8  // was TTL
	Version       uint8  // was TTL
	Z             uint16 // was TTL (all flags should be put here)
	Rdlength      uint16 // length of data after the header
*/

type RR_OPT struct {
	Hdr    RR_Header
	Option []Option  "OPT" // Tag is used in pack and unpack
}

// A ENDS packet must show differently. TODO
func (h *RR_Header) ednsString() string {
        return h.String()
}

func (rr *RR_OPT) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_OPT) String() string {
	s := rr.Hdr.ednsString() // Hier misschien andere representatie
	for _, o := range rr.Option {
		switch o.Code {
		case OptionCodeNSID:
			s += "NSID: " + o.Data
		}
	}
	return s
}

// when set is true, set the size otherwise get it
func (rr *RR_OPT) UDPSize(size int, set bool) int {
        // fiddle in rr.Hdr.Class should be set
        if set {
                rr.Hdr.Class = uint16(size)
        }
        return int(rr.Hdr.Class)
}

// when set is true, set the Do bit, otherwise get it
func (rr *RR_OPT) DoBit(do, set bool) bool {
        // rr.TTL last 2 bytes, left most bit
        if set {
                rr.Hdr.Ttl = 1
                return true
        } else {
                return true
        }
        return true // dead code, bug in Go
}

// when set is true, set the nsid, otherwise get it
func (rr *RR_OPT) Nsid(nsid string, set bool) string {
        // RR.Option[0] to be set
        return ""
}
