// TRANSACTION SIGNATURE (TSIG)
// 
// A TSIG or transaction signature adds a HMAC TSIG record to each message sent. 
// Basic use pattern when querying with TSIG:
//
//      m := new(Msg)
//      m.SetAxfr("miek.nl.")
//      // Add a stub TSIG record.
//      m.SetTsig("axfr.", HmacMD5, 300, uint64(time.Seconds()))
//      // Generate the contents of the complete TSIG record.
//      TsigGenerate(m, "so6ZGir4GPAqINNh9U5c3A==", "", false)
//      // A map holds all the secrets
//      secrets := make(map[string]string)      
//      secrets["axfr."] = "so6ZGir4GPAqINNh9U5c3A=="        // don't forget the . here
//
// The secrets' map index is set to 'axfr.'. This must match the ownername of the
// TSIG record, which in the above example, is also set to 'axfr.'
//
// The message requesting an AXFR (almost all TSIG usage is when requesting zone transfers)
// for miek.nl with the TSIG record added is now ready to use. 
// We now need a new client with access to the secrets:
//
//      c := NewClient()
//      c.TsigSecret = secrets
//      err := c.XfrReceive(m, "85.223.71.124:53")
//
// You can now read the records from the AXFR as they come in. Each envelope is checked with TSIG.
// If something is not correct an error is returned.
//
// Basic use pattern replying to a message that has TSIG set.
// TODO(mg)
//
package dns

import (
	"crypto/hmac"
	"crypto/md5"
        "crypto/sha1"
        "crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"time"
)

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

// TsigGenerate adds an TSIG RR to a message. The message should contain
// a "stub" TsigRR with the algorithm, key name (owner name of the RR), 
// time fudge (defaults to 300 seconds) and the current time
// The TSIG MAC is saved in that Tsig RR.
// When TsigGenerate is called for the
// first time requestMAC is set to the empty string.
// If something goes wrong an error is returned, otherwise it is nil.
func TsigGenerate(m *Msg, secret, requestMAC string, timersOnly bool) error {
	if !m.IsTsig() {
		// panic? panic?
		panic("TSIG not last RR in additional")
	}
	// If we barf here, the caller is to blame
	rawsecret, err := packBase64([]byte(secret))
	if err != nil {
		return err
	}

	rr := m.Extra[len(m.Extra)-1].(*RR_TSIG)
	m.Extra = m.Extra[0 : len(m.Extra)-1] // kill the TSIG from the msg
	mbuf, _ := m.Pack()
	buf := tsigBuffer(mbuf, rr, requestMAC, timersOnly)

	t := new(RR_TSIG)

        switch algo {

        }

        h := ""
        switch hmac {
        case rr.Algorithm:
                h = hmac.New(md5.New, []byte(rawsecret))
        case HmacSHA1:
	        h = hmac.New(sha1.New, []byte(rawsecret))
        case HmacSHA256:
	        h = hmac.New(sha256.New, []byte(rawsecret))
        default:
                return ErrKeyAlg
        }

	t.MAC = hex.EncodeToString(h.Sum(buf))
	t.MACSize = uint16(len(t.MAC) / 2) // Size is half!

	t.Hdr = RR_Header{Name: rr.Hdr.Name, Rrtype: TypeTSIG, Class: ClassANY, Ttl: 0}
	t.Fudge = rr.Fudge
	t.TimeSigned = rr.TimeSigned
	t.Algorithm = rr.Algorithm
	t.OrigId = m.MsgHdr.Id

	m.Extra = append(m.Extra, t)
	return nil
}

// TsigVerify verifies the TSIG on a message. 
// If the signature does not validate err contains the
// error, otherwise it is nil.
func TsigVerify(msg []byte, secret, requestMAC string, timersOnly bool) error {
	rawsecret, err := packBase64([]byte(secret))
	if err != nil {
		return err
	}
	// Srtip the TSIG from the incoming msg
	stripped, tsig, err := stripTsig(msg)
	if err != nil {
		return err
	}

	buf := tsigBuffer(stripped, tsig, requestMAC, timersOnly)

	ti := uint64(time.Now().Unix()) - tsig.TimeSigned
	if uint64(tsig.Fudge) < ti {
		return ErrTime
	}

        h := ""
        switch tsig.Algorithm {
        case rr.Algorithm:
                h = hmac.New(md5.New, []byte(rawsecret))
        case HmacSHA1:
	        h = hmac.New(sha1.New, []byte(rawsecret))
        case HmacSHA256:
	        h = hmac.New(sha256.New, []byte(rawsecret))
        default:
                return ErrKeyAlg
        }
	io.WriteString(h, string(buf))
	if strings.ToUpper(hex.EncodeToString(h.Sum(nil))) != strings.ToUpper(tsig.MAC) {
		return ErrSig
	}
	return nil
}

// Create a wiredata buffer for the MAC calculation.
func tsigBuffer(msgbuf []byte, rr *RR_TSIG, requestMAC string, timersOnly bool) []byte {
	var (
		macbuf []byte
		buf    []byte
	)
	if rr.TimeSigned == 0 {
		rr.TimeSigned = uint64(time.Now().Unix())
	}
	if rr.Fudge == 0 {
		rr.Fudge = 300 // Standard (RFC) default.
	}

	if requestMAC != "" {
		m := new(macWireFmt)
		m.MACSize = uint16(len(requestMAC) / 2)
		m.MAC = requestMAC
		macbuf = make([]byte, len(requestMAC)) // reqmac should be twice as long
		n, _ := packStruct(m, macbuf, 0)
		macbuf = macbuf[:n]
	}

	tsigvar := make([]byte, DefaultMsgSize)
	if timersOnly {
		tsig := new(timerWireFmt)
		tsig.TimeSigned = rr.TimeSigned
		tsig.Fudge = rr.Fudge
		n, _ := packStruct(tsig, tsigvar, 0)
		tsigvar = tsigvar[:n]
	} else {
		tsig := new(tsigWireFmt)
		tsig.Name = strings.ToLower(rr.Hdr.Name)
		tsig.Class = ClassANY
		tsig.Ttl = rr.Hdr.Ttl
		tsig.Algorithm = strings.ToLower(rr.Algorithm)
		tsig.TimeSigned = rr.TimeSigned
		tsig.Fudge = rr.Fudge
		tsig.Error = rr.Error
		tsig.OtherLen = rr.OtherLen
		tsig.OtherData = rr.OtherData
		n, _ := packStruct(tsig, tsigvar, 0)
		tsigvar = tsigvar[:n]
	}
	if rr.MAC != "" {
		x := append(macbuf, msgbuf...)
		buf = append(x, tsigvar...)
	} else {
		buf = append(msgbuf, tsigvar...)
	}
	return buf
}

// Strip the TSIG from the raw message
func stripTsig(msg []byte) ([]byte, *RR_TSIG, error) {
	// Copied from msg.go's Unpack()
	// Header.
	var dh Header
	dns := new(Msg)
	rr := new(RR_TSIG)
	off := 0
	tsigoff := 0
	var ok bool
	if off, ok = unpackStruct(&dh, msg, off); !ok {
		return nil, nil, ErrUnpack
	}
	if dh.Arcount == 0 {
		return nil, nil, ErrNoSig
	}
	// Rcode, see msg.go Unpack()
	if int(dh.Bits&0xF) == RcodeNotAuth {
		return nil, nil, ErrAuth
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
			rr = dns.Extra[i].(*RR_TSIG)
			// Adjust Arcount.
			arcount, _ := unpackUint16(msg, 10)
			msg[10], msg[11] = packUint16(arcount - 1)
			break
		}
	}
	if !ok {
		return nil, nil, ErrUnpack
	}
	if rr == nil {
		return nil, nil, ErrNoSig
	}
	return msg[:tsigoff], rr, nil
}
