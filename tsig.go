package dns

// Implementation of TSIG: generation and validation
// RFC 2845 and RFC 4635
import (
	"io"
	"strconv"
	"strings"
	"crypto/hmac"
	"encoding/hex"
)

// HMAC hashing codes. These are transmitted as domain names.
const (
	HmacMD5    = "hmac-md5.sig-alg.reg.int"
	HmacSHA1   = "hmac-sha1"
	HmacSHA256 = "hmac-sha256"
)

type RR_TSIG struct {
	Hdr        RR_Header
	Algorithm  string "domain-name"
	TimeSigned uint64
	Fudge      uint16
	MACSize    uint16
	MAC        string "size-hex"
	OrigId     uint16
	Error      uint16
	OtherLen   uint16
	OtherData  string "size-hex"
}

func (rr *RR_TSIG) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_TSIG) SetDefaults() {
        rr.Header().Ttl = 0
        rr.Header().Class = ClassANY
        rr.Header().Rrtype = TypeTSIG
        rr.Fudge = 300
}

// TSIG has no official presentation format, but this will suffice.
func (rr *RR_TSIG) String() string {
	return rr.Hdr.String() +
		" " + rr.Algorithm +
		" " + tsigTimeToDate(rr.TimeSigned) +
		" " + strconv.Itoa(int(rr.Fudge)) +
		" " + strconv.Itoa(int(rr.MACSize)) +
		" " + rr.MAC +
		" " + strconv.Itoa(int(rr.OrigId)) +
		" " + strconv.Itoa(int(rr.Error)) +
		" " + strconv.Itoa(int(rr.OtherLen)) +
		" " + rr.OtherData
}

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

// Generate the HMAC for message. The TSIG RR is modified
// to include the MAC and MACSize. Note the the msg Id must
// already be set, otherwise the MAC will not be correct when
// the message is send.
// The string 'secret' must be encoded in base64.
func (t *RR_TSIG) Generate(m *Msg, secret string) bool {
	rawsecret, err := packBase64([]byte(secret))
        if err != nil {
                return false
        }
	t.OrigId = m.MsgHdr.Id

	buf, ok := tsigToBuf(t, m)
	h := hmac.NewMD5([]byte(rawsecret))
	io.WriteString(h, string(buf))

	t.MAC = strings.ToUpper(hex.EncodeToString(h.Sum()))
	t.MACSize = uint16(len(h.Sum()))        // Needs to be "on-the-wire" size.
	if !ok {
		return false
	}
	return true
}

// Verify a TSIG. The message should be the complete with
// the TSIG record still attached (as the last rr in the Additional
// section). Return true on success.
// The secret is a base64 encoded string with the secret.
func (t *RR_TSIG) Verify(m *Msg, secret string) bool {
	// copy the mesg, strip (and check) the tsig rr
	// perform the opposite of Generate() and then 
	// verify the mac
	rawsecret, err := packBase64([]byte(secret))
        if err != nil {
                return false
        }

	msg2 := m // TODO deep copy TODO(mg)
	if len(msg2.Extra) < 1 {
		// nothing in additional
		return false
	}
        if t.Header().Rrtype != TypeTSIG {
                return false
        }
        msg2.MsgHdr.Id = t.OrigId
        msg2.Extra = msg2.Extra[:len(msg2.Extra)-1]     // Strip off the TSIG
        buf, ok := tsigToBuf(t, msg2)
        if !ok {
                return false
        }
        h := hmac.NewMD5([]byte(rawsecret))
        io.WriteString(h, string(buf))
        return strings.ToUpper(hex.EncodeToString(h.Sum())) == t.MAC
}

func tsigToBuf(rr *RR_TSIG, msg *Msg) ([]byte, bool) {
	// Fill the struct and generate the wiredata
	buf := make([]byte, DefaultMsgSize) // TODO(mg) bufsize!
	tsig := new(tsigWireFmt)
	tsig.Name = rr.Header().Name
	tsig.Class = rr.Header().Class
	tsig.Ttl = rr.Header().Ttl
	tsig.Algorithm = rr.Algorithm
	tsig.TimeSigned = rr.TimeSigned
	tsig.Fudge = rr.Fudge
	tsig.Error = rr.Error
	tsig.OtherLen = rr.OtherLen
	tsig.OtherData = rr.OtherData
	n, ok1 := packStruct(tsig, buf, 0)
	if !ok1 {
		return nil, false
	}
	buf = buf[:n]
	msgbuf, ok := msg.Pack()
	if !ok {
		return nil, false
	}
        // First the pkg, then the tsig wire fmt
	buf = append(msgbuf, buf...)
	return buf, true
}
