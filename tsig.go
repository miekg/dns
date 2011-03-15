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
	HmacMD5    = "hmac-md5.sig-alg.reg.int."
	HmacSHA1   = "hmac-sha1."
	HmacSHA256 = "hmac-sha256."
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
	rr.Algorithm = HmacMD5
}

// TSIG has no official presentation format, but this will suffice.
func (rr *RR_TSIG) String() string {
	return rr.Hdr.String() +
		" " + rr.Algorithm +
		" " + tsigTimeToDate(rr.TimeSigned) +
		" " + strconv.Itoa(int(rr.Fudge)) +
		" " + strconv.Itoa(int(rr.MACSize)) +
		" " + strings.ToUpper(rr.MAC) +
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

// If we have the MAC use this type to convert it to wiredata
type macWireFmt struct {
	MACSize uint16
	MAC     string "size-hex"
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

	buf, ok := tsigToBuf(t, m, "")
	h := hmac.NewMD5([]byte(rawsecret))
	io.WriteString(h, string(buf))

	t.MAC = hex.EncodeToString(h.Sum())
	t.MACSize = uint16(len(h.Sum())) // Needs to be "on-the-wire" size.
	if !ok {
		return false
	}
	return true
}

// Verify a TSIG. The message should be the complete with
// the TSIG record still attached (as the last rr in the Additional
// section). Return true on success.
// The secret is a base64 encoded string with the secret.
func (t *RR_TSIG) Verify(m []byte, secret, reqmac string) bool {
	rawsecret, err := packBase64([]byte(secret))
	if err != nil {
		return false
	}

	msg2 := m // Deep copy TODO(mg)
	if len(msg2.Extra) < 1 {
		// nothing in additional
		return false
	}
	if t.Header().Rrtype != TypeTSIG {
		return false
	}

	msg2.MsgHdr.Id = t.OrigId
	msg2.Extra = msg2.Extra[:len(msg2.Extra)-1] // Strip off the TSIG
	buf, ok := tsigToBuf(t, msg2, reqmac)
	if !ok {
		return false
	}

	h := hmac.NewMD5([]byte(rawsecret))
	io.WriteString(h, string(buf))
	println("t.MAC", strings.ToUpper(t.MAC))
	println("our MAC", strings.ToUpper(hex.EncodeToString(h.Sum())))
        println("req mac", reqmac)
	return strings.ToUpper(hex.EncodeToString(h.Sum())) == strings.ToUpper(reqmac)
}

func tsigToBuf(rr *RR_TSIG, msg *Msg, reqmac string) ([]byte, bool) {
	var mb []byte
        var buf []byte

	if reqmac != "" {
		m := new(macWireFmt)
		m.MACSize = uint16(len(reqmac) / 2)
		m.MAC = reqmac
		mb = make([]byte, len(reqmac)) // reqmac should be twice as long
		n, ok := packStruct(m, mb, 0)
		if !ok {
			return nil, false
		}
		mb = mb[:n]
	}

	tsigvar := make([]byte, DefaultMsgSize)
	tsig := new(tsigWireFmt)
	tsig.Name = strings.ToLower(rr.Header().Name)
	tsig.Class = rr.Header().Class
	tsig.Ttl = rr.Header().Ttl
	tsig.Algorithm = strings.ToLower(rr.Algorithm)
	tsig.TimeSigned = rr.TimeSigned
	tsig.Fudge = rr.Fudge
	tsig.Error = rr.Error
	tsig.OtherLen = rr.OtherLen
	tsig.OtherData = rr.OtherData
	n, ok1 := packStruct(tsig, tsigvar, 0)
	if !ok1 {
		return nil, false
	}
	tsigvar = tsigvar[:n]
	msgbuf, ok := msg.Pack()
	if !ok {
		return nil, false
	}
	if reqmac != "" {
                x := append(mb, msgbuf...)
		buf = append(x, tsigvar...)
	} else {
		buf = append(msgbuf, tsigvar...)
        }
	return buf, true
}

// Strip the TSIG from the pkt.
func stripTSIG(orig []byte) ([]byte, bool) {
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
                        msg[10], msg[11] = packUint16(arcount-1)
                        break
                }
        }
        if !ok {
                return nil, false
        }
        return msg[:tsigoff], true
}
