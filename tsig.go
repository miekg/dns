// TRANSACTION SIGNATURE (TSIG)
// 
// A TSIG or transaction signature adds a HMAC TSIG record to each message sent. 
// Basic use pattern when querying with TSIG:
//
//	m := new(Msg)
//	c := NewClient()
//	m.SetQuestion("miek.nl.", TypeMX)
//	// Set the secret under the name "axfr."
//	c.TsigSecret = map[string]string{"axfr.": "so6ZGir4GPAqINNh9U5c3A=="}	// don't forget the .
//	// Add the stub TSIG RR to the message
//	m.SetTsig("axfr.", HmacMD5, 300, uint64(time.Seconds()))
//	...
//	// When sending the TSIG RR is calculated and filled in before sending
//
// The supported algorithm include: HmacMD5, HmacSHA1 and HmacSHA256.
//
// AXFR (TODO)
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
// Basic use pattern validating and replying to a message that has TSIG set.
// TODO(mg)
//
package dns

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"hash"
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
	// From RR_Header
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

// TsigGenerate fills out the TSIG record attached to the message.
// The message should contain
// a "stub" TSIG RR with the algorithm, key name (owner name of the RR), 
// time fudge (defaults to 300 seconds) and the current time       
// The TSIG MAC is saved in that Tsig RR.                          
// When TsigGenerate is called for the first time requestMAC is set to the empty string and
// timersOnly is false.                                            
// If something goes wrong an error is returned, otherwise it is nil. 
func TsigGenerate(m *Msg, secret, requestMAC string, timersOnly bool) ([]byte, string, error) {
	if !m.IsTsig() {
		panic("TSIG not last RR in additional")
	}
	// If we barf here, the caller is to blame
	rawsecret, err := packBase64([]byte(secret))
	if err != nil {
		return nil, "", err
	}

	rr := m.Extra[len(m.Extra)-1].(*RR_TSIG)
	m.Extra = m.Extra[0 : len(m.Extra)-1] // kill the TSIG from the msg
	mbuf, ok := m.Pack()
	if !ok {
		return nil, "", ErrPack
	}
	buf := tsigBuffer(mbuf, rr, requestMAC, timersOnly)

	t := new(RR_TSIG)
	var h hash.Hash
	switch rr.Algorithm {
	case HmacMD5:
		h = hmac.New(md5.New, []byte(rawsecret))
	case HmacSHA1:
		h = hmac.New(sha1.New, []byte(rawsecret))
	case HmacSHA256:
		h = hmac.New(sha256.New, []byte(rawsecret))
	default:
		return nil, "", ErrKeyAlg
	}
	io.WriteString(h, string(buf))
	t.MAC = hex.EncodeToString(h.Sum(nil))
	t.MACSize = uint16(len(t.MAC) / 2) // Size is half!

	t.Hdr = RR_Header{Name: rr.Hdr.Name, Rrtype: TypeTSIG, Class: ClassANY, Ttl: 0}
	t.Fudge = rr.Fudge
	t.TimeSigned = rr.TimeSigned
	t.Algorithm = rr.Algorithm
	t.OrigId = m.MsgHdr.Id

	tbuf := make([]byte, t.Len())
	if off, ok := packRR(t, tbuf, 0, nil, false); ok {
		tbuf = tbuf[:off] // reset to actual size used
	} else {
		return nil, "", ErrPack
	}
	mbuf = append(mbuf, tbuf...)
	RawSetExtraLen(mbuf, uint16(len(m.Extra)+1))
	return mbuf, t.MAC, nil
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

	var h hash.Hash
	switch tsig.Algorithm {
	case HmacMD5:
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
