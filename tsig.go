package dns

import (
	"io"
	"os"
	"time"
	"strings"
	"crypto/hmac"
	"encoding/hex"
)

// The structure Tsig is used in Read/Write functions to
// add or remove a TSIG on a dns message. See RFC 2845
// and RFC 4635.
// Basic use pattern of Tsig:
//
//      tsig := new(dns.Tsig)
//      tsig.Name = "axfr."                      // The name of the key.
//      tsig.Algorithm = dns.HmacMD5             // The HMAC to use.
//      tsig.Fudge = 300                         // RFC recommends 300 here.
//      tsig.TimeSigned = uint64(time.Seconds())      
//      tsig.Secret = "so6ZGir4GPAqINNh9U5c3A==" // Secret encoded in base64.

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

// Add a Tsig to an message. // Must return the mac
func TsigGenerate(m *Msg, secret string, timersOnly bool) (*Msg, os.Error) {
        if !m.IsTsig() {
                panic("TSIG not last RR in additional")
        }
	rawsecret, err := packBase64([]byte(secret))
	if err != nil {
		return nil, err
	}

        rr := m.Extra[len(m.Extra)-1].(*RR_TSIG)
        m.Extra = m.Extra[0:len(m.Extra)-1]     // kill the TSIG from the msg
	buf, err := tsigBuffer(m, rr, timersOnly)
	if err != nil {
		return nil, err
	}

	t := new(RR_TSIG)

	h := hmac.NewMD5([]byte(rawsecret))
	io.WriteString(h, string(buf))
	t.MAC = hex.EncodeToString(h.Sum()) // Size is half!

	t.Hdr = RR_Header{Name: rr.Hdr.Name, Rrtype: TypeTSIG, Class: ClassANY, Ttl: 0}
	t.Fudge = t.Fudge
	t.TimeSigned = t.TimeSigned
	t.Algorithm = t.Algorithm
	t.OrigId = m.MsgHdr.Id
	t.MAC = t.MAC
	t.MACSize = uint16(len(t.MAC) / 2)

	m.Extra = append(m.Extra, t)
        return m, nil
}

/*
// Verify a TSIG on a message. 
// If the signature does not validate err contains the
// error. If the it validates err is nil
func (t *Tsig) Verify(msg []byte) (bool, os.Error) {
	rawsecret, err := packBase64([]byte(t.Secret))
	if err != nil {
		return false, err
	}
	// Stipped the TSIG from the incoming msg
	stripped, err := t.stripTsig(msg)
	if err != nil {
		return false, err
	}

	buf, err := t.Buffer(stripped)
	if err != nil {
		return false, err
	}

	// Time needs to be checked

	h := hmac.NewMD5([]byte(rawsecret))
	io.WriteString(h, string(buf))
	return strings.ToUpper(hex.EncodeToString(h.Sum())) == strings.ToUpper(t.MAC), nil
}
*/

// Create a wiredata buffer for the MAC calculation.
func tsigBuffer(msg *Msg, rr *RR_TSIG, timersOnly bool) ([]byte, os.Error) {
	var (
		macbuf []byte
		buf    []byte
	)
        if rr.TimeSigned == 0 {
                rr.TimeSigned = uint64(time.Seconds())
        }
        if rr.Fudge == 0 {
                rr.Fudge = 300
        }

	if rr.MAC != "" {
		m := new(macWireFmt)
		m.MACSize = uint16(len(rr.MAC) / 2)
		m.MAC = rr.MAC
		macbuf = make([]byte, len(rr.MAC)) // reqmac should be twice as long
		n, ok := packStruct(m, macbuf, 0)
		if !ok {
			return nil, ErrSigGen
		}
		macbuf = macbuf[:n]
	}

	tsigvar := make([]byte, DefaultMsgSize)
	if timersOnly {
		tsig := new(timerWireFmt)
		tsig.TimeSigned = rr.TimeSigned
		tsig.Fudge = rr.Fudge
		n, ok1 := packStruct(tsig, tsigvar, 0)
		if !ok1 {
			return nil, ErrSigGen
		}
		tsigvar = tsigvar[:n]
	} else {
		tsig := new(tsigWireFmt)
		tsig.Name = strings.ToLower(rr.Hdr.Name)
		tsig.Class = ClassANY
		tsig.Ttl = 0
		tsig.Algorithm = strings.ToLower(rr.Algorithm)
		tsig.TimeSigned = rr.TimeSigned
		tsig.Fudge = rr.Fudge
		tsig.Error = 0
		tsig.OtherLen = 0
		tsig.OtherData = ""
		n, ok1 := packStruct(tsig, tsigvar, 0)
		if !ok1 {
			return nil, ErrSigGen
		}
		tsigvar = tsigvar[:n]
	}
	if rr.MAC != "" {
                msgbuf, _ := msg.Pack()
		x := append(macbuf, msgbuf...)
		buf = append(x, tsigvar...)
	} else {
                msgbuf, _ := msg.Pack()
		buf = append(msgbuf, tsigvar...)
	}
	return buf, nil
}
/*
// Strip the TSIG from the pkt.
func (t *Tsig) stripTsig(orig []byte) ([]byte, os.Error) {
	// Copied from msg.go's Unpack()
	// Header.
	var dh Header
	dns := new(Msg)
	msg := make([]byte, len(orig))
	copy(msg, orig) // fhhh.. another copy TODO(mg)?
	off := 0
	tsigoff := 0
	var ok bool
	if off, ok = unpackStruct(&dh, msg, off); !ok {
		return nil, ErrUnpack
	}
	if dh.Arcount == 0 {
		return nil, ErrNoSig
	}
        // Rcode, see msg.go Unpack()
        if int(dh.Bits & 0xF) == RcodeNotAuth {
                return nil, ErrAuth
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
                        if t.Name != "" {
                                if t.Name != dns.Extra[i].Header().Name {
                                        return nil, ErrKey
                                }
                        }
                        if t.Algorithm != "" {
                                if t.Algorithm != dns.Extra[i].(*RR_TSIG).Algorithm {
                                        return nil, ErrAlg
                                }
                        }
                        ti := uint64(time.Seconds()) - dns.Extra[i].(*RR_TSIG).TimeSigned
                        if uint64(dns.Extra[i].(*RR_TSIG).Fudge) < ti {
                                return nil, ErrTime
                        }
			// Adjust Arcount.
			arcount, _ := unpackUint16(msg, 10)
			msg[10], msg[11] = packUint16(arcount - 1)
			break
		}
	}
	if !ok {
		return nil, ErrUnpack
	}
	return msg[:tsigoff], nil
}
*/
