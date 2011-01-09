package dns

// Implementation of TSIG
// Generation an Validation

import (
	"crypto/hmac"
	"strconv"
	"io"
)

// Need to lookup the actual codes
const (
	HmacMD5 = iota
	HmacSHA1
)

type RR_TSIG struct {
	Hdr        RR_Header
	Algorithm  string   "domain-name"
	TimeSigned uint64
	Fudge      uint16
	MACSize    uint16
	MAC        string
	OrigId     uint16 // msg id
	Error      uint16
	OtherLen   uint16
	OtherData  string
}

func (rr *RR_TSIG) Header() *RR_Header {
	return &rr.Hdr
}

func (rr *RR_TSIG) String() string {
	// It has no presentation format
	return rr.Hdr.String() +
		" " + rr.Algorithm +
		" " + "<timesigned>" +
		" " + strconv.Itoa(int(rr.Fudge)) +
		" " + "<MAC>" +
		" " + strconv.Itoa(int(rr.OrigId)) +
		" " + strconv.Itoa(int(rr.Error)) +
		" " + rr.OtherData
}

// The following values must be put in wireformat, so that
// the MAC can be calculated
// RFC 2845, section 3.4.2. TSIG Variables
type tsig_generation_fmt struct {
	// From RR_HEADER
	Name  string "domain-name"
	Class uint16
	Ttl   uint32
	// Rdata of the TSIG
	Algorithm  string   "domain-name"
	TimeSigned uint64
	Fudge      uint16
	// MACSize, MAC and OrigId excluded
	Error     uint16
	OtherLen  uint16
	OtherData string
}

// Generate the HMAC for msg. The TSIG RR is modified
// to include the MAC and MACSize. Note the the msg Id must
// be set, otherwise the MAC is not correct
func (rr *RR_TSIG) Generate(msg *Msg, secret string) bool {
	buf := make([]byte, 4096) // TODO(mg) bufsize!
	tsig := new(tsig_generation_fmt)

	// Fill the struct and generate the wiredata
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
		return false
	}
	buf = buf[:n]

	msgbuf, ok := msg.Pack()
	if !ok {
		return false
	}
	buf = append(buf, msgbuf...)

	hmac := hmac.NewMD5([]byte(secret))
	io.WriteString(hmac, string(buf))
	rr.MAC = string(hmac.Sum())
	rr.MACSize = uint16(len(rr.MAC))
	rr.OrigId = msg.MsgHdr.Id
	return true
}

// Verify a TSIG. The msg should be the complete message with
// the TSIG record still attached (as the last rr in the Additional
// section)
func (rr *RR_TSIG) Verify(msg *Msg, secret string) bool {
	// copy the mesg, strip (and check) the tsig rr
	// perform the opposite of Generate() and then 
	// verify the mac
	return false
}
