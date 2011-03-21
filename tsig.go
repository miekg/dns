package dns

// Implementation of TSIG: generation and validation
// RFC 2845 and RFC 4635
import (
	"io"
        "os"
        "time"
	"strings"
	"crypto/hmac"
	"encoding/hex"
)

// Return os.Error with real tsig errors

// Structure used in Read/Write lowlevel functions
// for TSIG generation and verification.
type Tsig struct {
	// The name of the key.
	Name       string
	Fudge      uint16
	TimeSigned uint64
	Algorithm  string
	// Tsig secret encoded in base64.
	Secret string
	// MAC (if known)
	MAC string
	// Request MAC
	RequestMAC string
	// Only include the timers if true.
	TimersOnly bool
}

// HMAC hashing codes. These are transmitted as domain names.
const (
	HmacMD5    = "hmac-md5.sig-alg.reg.int."
	HmacSHA1   = "hmac-sha1."
	HmacSHA256 = "hmac-sha256."
)

// The following values must be put in wireformat, so that the MAC can be calculated.
// RFC 2845, section 3.4.2. TSIG Variables.
type tsigWireFmt struct {
	// From RR_HEADER
	Name  string "domain-name"
	Class uint16
	Ttl   uint32
	// Rdata of the TSIG
	Algorithm  string "domain-name"
	TimeSigned uint64
	Fudge      uint16
	// MACSize, MAC and OrigId excluded
	Error     uint16
	OtherLen  uint16
	OtherData string "size-hex"
}

// If we have the MAC use this type to convert it to wiredata.
// Section 3.4.3. Request MAC
type macWireFmt struct {
	MACSize uint16
	MAC     string "size-hex"
}

// 3.3. Time values used in TSIG calculations
type timerWireFmt struct {
	TimeSigned uint64
	Fudge      uint16
}

// In a message and out a new message with the tsig added
func (t *Tsig) Generate(msg []byte) ([]byte, os.Error) {
	rawsecret, err := packBase64([]byte(t.Secret))
	if err != nil {
		return nil, err
	}
        if t.Fudge == 0 {
                t.Fudge = 300
        }
        if t.TimeSigned == 0 {
                t.TimeSigned = uint64(time.Seconds())
        }

	buf, err := t.Buffer(msg)
	if err != nil {
		return nil, err
	}
	h := hmac.NewMD5([]byte(rawsecret))
	io.WriteString(h, string(buf))
	t.MAC = hex.EncodeToString(h.Sum()) // Size is half!

	// Create TSIG and add it to the message.
        q := new(Msg)
        if !q.Unpack(msg) {
                return nil, &Error{Error: "Failed to unpack"}
        }

	rr := new(RR_TSIG)
	rr.Hdr = RR_Header{Name: t.Name, Rrtype: TypeTSIG, Class: ClassANY, Ttl: 0}
        rr.Fudge = t.Fudge
        rr.TimeSigned = t.TimeSigned
        rr.Algorithm = t.Algorithm
        rr.OrigId = q.Id
	rr.MAC = t.MAC
	rr.MACSize = uint16(len(t.MAC) / 2)

        q.Extra = append(q.Extra, rr)
        send, ok := q.Pack()
        if !ok {
                return send, &Error{Error: "Failed to pack"}
        }
	return send, nil
}

// Verify a TSIG on a message. All relevant data should
// be set in the Tsig structure.
func (t *Tsig) Verify(msg []byte) (bool, os.Error) {
	rawsecret, err := packBase64([]byte(t.Secret))
	if err != nil {
		return false, err
	}
	// Stipped the TSIG from the incoming msg
	stripped, ok := stripTsig(msg)
	if !ok {
		return false, &Error{Error: "Failed to strip tsig"}
	}

	buf,err := t.Buffer(stripped)
	if err != nil {
		return false, err
	}

        // Time needs to be checked */
        // Generic time error

	h := hmac.NewMD5([]byte(rawsecret))
	io.WriteString(h, string(buf))
	return strings.ToUpper(hex.EncodeToString(h.Sum())) == strings.ToUpper(t.MAC), nil
}

// Create a wiredata buffer for the MAC calculation
func (t *Tsig) Buffer(msg []byte) ([]byte, os.Error) {
	var (
		macbuf []byte
		buf    []byte
	)

	if t.RequestMAC != "" {
		m := new(macWireFmt)
		m.MACSize = uint16(len(t.RequestMAC) / 2)
		m.MAC = t.RequestMAC
		macbuf = make([]byte, len(t.RequestMAC)) // reqmac should be twice as long
		n, ok := packStruct(m, macbuf, 0)
		if !ok {
		        return nil, &Error{Error: "Failed to pack request mac"}
		}
		macbuf = macbuf[:n]
	}

	tsigvar := make([]byte, DefaultMsgSize)
	if t.TimersOnly {
		tsig := new(timerWireFmt)
		tsig.TimeSigned = t.TimeSigned
		tsig.Fudge = t.Fudge
		n, ok1 := packStruct(tsig, tsigvar, 0)
		if !ok1 {
		        return nil, &Error{Error: "Failed to pack timers"}
		}
		tsigvar = tsigvar[:n]
	} else {
		tsig := new(tsigWireFmt)
		tsig.Name = strings.ToLower(t.Name)
		tsig.Class = ClassANY
		tsig.Ttl = 0
		tsig.Algorithm = strings.ToLower(t.Algorithm)
		tsig.TimeSigned = t.TimeSigned
		tsig.Fudge = t.Fudge
		tsig.Error = 0
		tsig.OtherLen = 0
		tsig.OtherData = ""
		n, ok1 := packStruct(tsig, tsigvar, 0)
		if !ok1 {
		        return nil, &Error{Error: "Failed to pack tsig variables"}
		}
		tsigvar = tsigvar[:n]
	}
	if t.RequestMAC != "" {
		x := append(macbuf, msg...)
		buf = append(x, tsigvar...)
	} else {
		buf = append(msg, tsigvar...)
	}
	return buf, nil
}

// Strip the TSIG from the pkt.
func stripTsig(orig []byte) ([]byte, bool) {
	// Copied from msg.go's Unpack()
	// Header.
	var dh Header
	dns := new(Msg)
	msg := make([]byte, len(orig))
	copy(msg, orig) // fhhh.. another copy
	off := 0
	tsigoff := 0
	var ok bool
	if off, ok = unpackStruct(&dh, msg, off); !ok {
		return nil, false
	}
	if dh.Arcount == 0 {
		// No records at all in the additional.
		return nil, false
	}

	// Arrays.
	dns.Question = make([]Question, dh.Qdcount)
	dns.Answer = make([]RR, dh.Ancount)
	dns.Ns = make([]RR, dh.Nscount)
	dns.Extra = make([]RR, dh.Arcount)

	for i := 0; i < len(dns.Question); i++ {
		off, ok = unpackStruct(&dns.Question[i], msg, off)
	}
	for i := 0; i < len(dns.Answer); i++ {
		dns.Answer[i], off, ok = unpackRR(msg, off)
	}
	for i := 0; i < len(dns.Ns); i++ {
		dns.Ns[i], off, ok = unpackRR(msg, off)
	}
	for i := 0; i < len(dns.Extra); i++ {
		tsigoff = off
		dns.Extra[i], off, ok = unpackRR(msg, off)
		if dns.Extra[i].Header().Rrtype == TypeTSIG {
			// Adjust Arcount.
			arcount, _ := unpackUint16(msg, 10)
			msg[10], msg[11] = packUint16(arcount - 1)
			break
		}
	}
	if !ok {
		return nil, false
	}
	return msg[:tsigoff], true
}
